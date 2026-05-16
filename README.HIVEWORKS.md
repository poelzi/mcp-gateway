# Hiveworks fork of `mcp-gateway`

This repository is a long-lived fork of [`MikkoParkkola/mcp-gateway`](https://github.com/MikkoParkkola/mcp-gateway) maintained for embedding the MCP federation surface inside `hiveworksd`. The upstream crate is published as a standalone gateway binary; this fork extracts a clean, embeddable library API so MCP protocol handling can run inside another axum/tower application without the upstream's auth middleware, management routes, web UI, or PolyForm-licensed Enterprise Edition surface.

## Why fork

Phase 0 of the [Hiveworks LLM gateway migration plan](https://github.com/poelzi/Projects-hive-hiveworks/blob/main/docs/plan/phase0-findings.md) established three blockers against using upstream `mcp-gateway` 2.11.0 as-is:

1. **`AppState` and `create_router()` are not public API.** `src/gateway/mod.rs:41-46` re-exports them under `pub mod test_helpers` with the docstring *"Hidden from docs; only used in the `tests/` directory."* External embedders have no public surface.
2. **`create_router()` bakes in upstream auth.** `src/gateway/router/mod.rs:134` applies `auth_middleware` unconditionally. Mounting under another tower stack (e.g. `hiveworksd`'s `require_gateway_token`) double-authenticates every request.
3. **Top-level management routes bleed into the host namespace.** `create_router()` publishes `/health`, `/api/costs`, `/.well-known/jwks.json`, `/sse` deprecation, optional `/metrics`, and web UI HTML alongside the MCP protocol routes (`/mcp`, `/mcp/{name}`, `/mcp/{name}/{*path}`). `.nest("/mcp", create_router(...))` puts non-MCP gateway-management URLs at `/mcp/health`, `/mcp/api/costs`, etc.

The detangle work in this fork carves out a small public surface dedicated to **MCP protocol federation only**, leaving the upstream's standalone-gateway-binary use case untouched and (where practical) unchanged.

## Licensing constraint

Upstream v2.11.0 activated [dual-licensing](./LICENSE-EE.md): the bulk of the crate stays MIT, but 27 files are designated Enterprise Edition (EE) under [PolyForm-Noncommercial-1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/), notably:

- `src/security/firewall/`
- `src/security/agent_identity.rs`, `data_flow.rs`, `message_signing.rs`, `policy.rs`, `response_inspect.rs`, `response_scanner.rs`, `scope_collision.rs`, `tool_integrity.rs`
- `src/cost_accounting/`
- `src/key_server/`
- `src/transparency_log/`

Hiveworks's commercial use case is incompatible with PolyForm-Noncommercial on these files. The detangle naturally trims the embedded surface away from these modules — they are gateway-binary concerns, not MCP-protocol concerns — but the unmodified crate compiles them unconditionally (see `src/lib.rs` `pub mod cost_accounting;` `pub mod key_server;`). Strategy:

- The new embedding API (`pub fn mcp_protocol_router(...)` and the slim state types added in this fork) **must not transitively depend on EE-licensed code paths**.
- Upstream binary code paths (`src/main.rs`, `src/gateway/server.rs`, the existing `create_router()`, etc.) remain compiled as-is on `main` for upstream parity; downstream consumers that only use the embedding API and `default-features = false` get a build that *links* the EE modules but does not *invoke* them. We will revisit excising the EE modules outright (via `#[cfg(feature = "ee")]` or deletion) in a follow-up branch if downstream legal review demands a cleaner separation.

If Hiveworks ends up shipping any code path that reaches an EE function — even indirectly — the legal status flips. The detangle commits should document, per change, what new code touches EE modules.

## Branch layout

| Branch | Purpose | Tracking |
| --- | --- | --- |
| `main` | Mirror of `upstream/main`. Never carries Hiveworks-specific commits. | `upstream/main` |
| `hiveworks/detangle-router` | All Hiveworks detangle work. Rebased onto new upstream releases. | `origin/hiveworks/detangle-router` |
| `hiveworks/release/x.y.z-hw.N` | Pinned snapshots consumed by `hiveworks/Cargo.toml`. Cut from `hiveworks/detangle-router` at known-good points. | tagged |

Remote `upstream` points at `MikkoParkkola/mcp-gateway`. Remote `origin` points at `poelzi/mcp-gateway`.

### Upstream merge procedure

When upstream cuts a new release:

```sh
git fetch upstream --tags
git checkout main && git merge --ff-only upstream/main && git push origin main
git checkout hiveworks/detangle-router
git rebase v<new-version>
# resolve conflicts hunk-by-hunk per Hiveworks AGENTS.md §11 (no -X ours / -X theirs)
just check          # at this point we are inside the hiveworks repo's nix devshell; mcp-gateway uses upstream's `cargo` directly
cargo test --no-default-features
git push --force-with-lease origin hiveworks/detangle-router
# bump the pinned release snapshot if downstream needs it:
git tag hiveworks/release/<new-version>-hw.1
git push origin hiveworks/release/<new-version>-hw.1
```

`--force-with-lease` (never plain `--force`) protects against clobbering concurrent work.

### Downstream consumption (hiveworks repo)

`hiveworks/Cargo.toml`:

```toml
mcp-gateway = { git = "https://github.com/poelzi/mcp-gateway.git", tag = "hiveworks/release/2.11.0-hw.1", default-features = false }
```

Use **tags**, not branches, so the lockfile pins a specific SHA and CI cannot silently drift when this branch advances.

## Detangle objectives

In dependency order:

1. **Add a public `pub fn mcp_protocol_router(state: Arc<AppState>) -> Router`** that returns only `/mcp` (POST/GET/DELETE), `/mcp/{name}` (POST), and `/mcp/{name}/{*path}` (POST), with no `auth_middleware`, no `CompressionLayer`, no `CatchPanicLayer`, no management routes, no JWKS, no key-server, no web UI, no `/metrics`. Caller wraps it with their own middleware. Re-exports `pub use gateway::embed::{mcp_protocol_router, McpRoutes};` at the crate root.
2. **Promote `AppState` to `pub use` from `gateway::embed`** alongside the function, **document the construction surface**, and add a builder (`AppStateBuilder`) that accepts only the fields the new router actually reads. Optional fields (`KeyServer`, `Firewall`, web UI dirs, `config_path`) default to disabled.
3. **Split `AppState` into composable parts.** `McpState` (backends, meta_mcp, multiplexer, proxy_manager, streaming_config, sanitize_input, ssrf_protection, inflight); `AuthInfra` (auth_config, agent_auth, gateway_key_pair, key_server); `PolicyState` (tool_policy, mtls_policy, firewall, agent_identity_config). The legacy `AppState` becomes a thin facade so upstream's `create_router()` keeps compiling.
4. **Make Meta-MCP optional in the embedding path.** Today `meta_mcp_enabled: bool` flips behavior inside the handler, but the `/mcp` POST handler always runs through `MetaMcp`. An embedder may want pure passthrough (`/mcp/{name}` only). Add an explicit "passthrough-only" router variant (`mcp_passthrough_router`) that drops the `/mcp` POST/GET/DELETE handlers entirely.
5. **Strip transitive EE coupling.** Confirm via `cargo tree --no-default-features` that nothing in the embedding API path reaches `cost_accounting`, `key_server`, `transparency_log`, or PolyForm-licensed files in `security/`. Where coupling exists, refactor or feature-gate. This is the precondition for shipping commercially.
6. **Carry an integration test in `tests/embed_smoke.rs`** that builds a minimal `AppState`, mounts `mcp_protocol_router` under a host axum app, registers a stdio backend (`mcp-server-everything` via `npx`), and round-trips `tools/list` and one `tools/call`. Confirms the embedding API survives upstream merges.

Each item above lands as its own commit (or small commit chain) on `hiveworks/detangle-router`, with a `feat(embed): ...` or `refactor(embed): ...` prefix so upstream cherry-picks remain easy.

## Upstreaming policy

We will offer items 1, 2, 3, and 6 to upstream as PRs once the detangle stabilizes — they are non-controversial library-API additions. Items 4 and 5 are Hiveworks-specific and will not be upstreamed. If upstream accepts (1)/(2)/(3)/(6), this fork's diff shrinks accordingly.

## Current status

| # | Status | Notes |
| --- | --- | --- |
| 1 | partial — bare router + middleware-composition helpers landed | `mcp_protocol_router()` shipped (commit `5944e63`); `with_auth` / `with_agent_auth` Router-decorator helpers and a `check_agent_scope_and_audit` re-export shipped under `mcp_gateway::embed` (commit-2). A `tower::Layer` constructor pair (`embed::layer::*`) was prototyped but dropped: axum's `FromFnLayer<F, S, T>` parameterizes on the `async fn` item type `F` which is unnameable, so an `impl Layer<S>` return cannot uniquely determine the phantom marker `T`. Embedders who need `ServiceBuilder`-style composition call `axum::middleware::from_fn_with_state` directly with the re-exported middleware functions (documented in `embed`'s rustdoc Pattern C). |
| 2 | partial | `McpState` slim type + `into_app_state` conversion landed (commit-3). Builder for sensible defaults of `MetaMcp`/`NotificationMultiplexer`/`StreamingConfig`/`ToolPolicy`/`MtlsPolicy` still pending — currently the host constructs those by struct literal. |
| 3 | partial | `McpState` excludes upstream's `auth_config`, `key_server` (PolyForm-EE), `agent_auth`, `gateway_key_pair`, `capability_dirs`, `config_path`, and the cfg-gated `firewall` (PolyForm-EE) fields. Embedders no longer see `KeyServer` in their type graph via the slim path. **Residual EE linkage**: `AgentIdentityConfig` (PolyForm-EE) stays in `McpState` because handlers read it on every tool invocation; default-constructing it (`enabled: false`) keeps the runtime path on MIT code. Fully eliminating that linkage requires either an upstream change (move `AgentIdentityConfig` to MIT) or a fork-side feature gate on the field. |
| 4 | pending | Optional — only if downstream needs passthrough-only mode. |
| 5 | pending | Legal gate for commercial shipping. |
| 6 | pending | Required before declaring the fork merge-ready. |

See commits on `hiveworks/detangle-router` for live progress.
