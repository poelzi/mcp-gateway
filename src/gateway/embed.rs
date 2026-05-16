//! Public embedding API for hosts that mount the MCP protocol surface inside
//! their own axum/tower application.
//!
//! In contrast to upstream's `create_router()` (which is `#[doc(hidden)] pub`
//! under `gateway::test_helpers` and bakes in `auth_middleware`,
//! `agent_auth_middleware`, gateway-management routes, JWKS, the key server,
//! the web UI, and `/metrics`), this module exposes only what an embedder
//! needs:
//!
//! - [`mcp_protocol_router`] — a router with only `/mcp`, `/mcp/{name}`, and
//!   `/mcp/{name}/{*path}`, **no** middleware layers attached.
//! - Re-exports of the upstream middleware functions and their state types
//!   ([`auth_middleware`], [`agent_auth_middleware`], [`AuthState`],
//!   [`AgentAuthState`], etc.) so embedders can opt in to mcp-gateway's
//!   existing auth implementations selectively.
//! - Ergonomic composers — [`with_auth`] / [`with_agent_auth`] for the
//!   common Router-decorator pattern.
//! - [`check_agent_scope_and_audit`] — the handler-time helper that pairs
//!   with `agent_auth_middleware` for per-tool scope enforcement and audit
//!   logging.
//!
//! See `README.HIVEWORKS.md` at the repo root for the design rationale and
//! the fork's branching strategy.
//!
//! # Layer ordering
//!
//! axum's [`axum::Router::layer`] semantics: the **later** `.layer()` call
//! applies the **outermost** wrapper, which means it runs **first** on each
//! request. Upstream's `create_router` composes layers as
//! `routes.layer(agent_auth).layer(auth).layer(tower_http_layers)`, so on
//! the request path `auth_middleware` fires first, then
//! `agent_auth_middleware`, then handlers.
//!
//! To match that ordering with the helpers below:
//!
//! ```rust,ignore
//! // CORRECT — auth runs first, then agent_auth, then handlers.
//! let router = with_agent_auth(
//!     with_auth(mcp_protocol_router(state), auth_state),
//!     agent_auth_state,
//! );
//! ```
//!
//! Reversing the nesting silently flips the order:
//!
//! ```rust,ignore
//! // WRONG — agent_auth runs before auth; JWT validity is enforced on
//! // requests that should have been short-circuited by auth's public-path
//! // bypass.
//! let router = with_auth(
//!     with_agent_auth(mcp_protocol_router(state), agent_auth_state),
//!     auth_state,
//! );
//! ```
//!
//! # Examples
//!
//! ## Pattern A — standalone (host supplies its own auth)
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use axum::Router;
//! use mcp_gateway::embed::{mcp_protocol_router, AppState};
//!
//! # fn make_state() -> Arc<AppState> { unimplemented!() }
//! # fn host_auth<S: Clone + Send + Sync + 'static>(r: Router<S>) -> Router<S> { r }
//! let state = make_state();
//! // Host wraps the bare MCP router with whatever it likes.
//! let router: Router = host_auth(mcp_protocol_router(state));
//! ```
//!
//! ## Pattern B — Router-decorator (reuse mcp-gateway's auth layers)
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use mcp_gateway::embed::{
//!     mcp_protocol_router, with_auth, with_agent_auth,
//!     AppState, AuthState, AgentAuthState,
//! };
//!
//! # fn make_state() -> Arc<AppState> { unimplemented!() }
//! # fn make_auth() -> AuthState { unimplemented!() }
//! # fn make_agent() -> AgentAuthState { unimplemented!() }
//! let router = with_agent_auth(
//!     with_auth(mcp_protocol_router(make_state()), make_auth()),
//!     make_agent(),
//! );
//! ```
//!
//! ## Pattern C — mix with host layers (manual `from_fn_with_state`)
//!
//! For embedders who compose middleware via [`tower::ServiceBuilder`] or
//! who need to interleave mcp-gateway's auth layers with host layers in
//! arbitrary positions, call [`axum::middleware::from_fn_with_state`]
//! directly with the re-exported middleware functions:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use axum::middleware::from_fn_with_state;
//! use mcp_gateway::embed::{
//!     mcp_protocol_router, auth_middleware, agent_auth_middleware,
//!     AppState, AuthState, AgentAuthState,
//! };
//!
//! # fn make_state() -> Arc<AppState> { unimplemented!() }
//! # fn make_auth() -> AuthState { unimplemented!() }
//! # fn make_agent() -> AgentAuthState { unimplemented!() }
//! let router = mcp_protocol_router(make_state())
//!     .layer(from_fn_with_state(make_agent(), agent_auth_middleware))
//!     .layer(from_fn_with_state(make_auth(),  auth_middleware));
//! ```
//!
//! A wrapper `embed::layer::{auth, agent_auth}` returning `tower::Layer`
//! constructors was considered but is not viable in stable Rust: axum's
//! `FromFnLayer<F, S, T>` parameterizes on the `async fn` item type `F`,
//! which is unnameable, so an `impl Layer<S>` return type cannot uniquely
//! determine the phantom marker `T`. Calling `from_fn_with_state` at the
//! `.layer()` site (as above) is the workable pattern.

use axum::{Router, middleware};

// Re-exports — single discoverable surface for embedders. All items below
// are already `pub` at their definition sites; bringing them under
// `embed::*` gives one canonical import path.
pub use super::auth::{AuthState, ResolvedAuthConfig, auth_middleware};
pub use super::meta_mcp::MetaMcp;
pub use super::oauth::{
    AgentAuthState, AgentIdentity, AgentRegistry, GatewayKeyPair, agent_auth_middleware,
    check_agent_scope_and_audit,
};
pub use super::router::{AppState, mcp_protocol_router};

/// Wrap `router` with mcp-gateway's bearer-token / API-key authentication
/// middleware ([`auth_middleware`]).
///
/// The wrapped router validates `Authorization: Bearer ...` and API-key
/// headers per the supplied [`AuthState`], enforces per-client rate
/// limiting, and short-circuits a configured set of public paths. See
/// [`AuthState`] and [`ResolvedAuthConfig`] for configuration details.
///
/// Equivalent to:
/// ```rust,ignore
/// router.layer(axum::middleware::from_fn_with_state(state, auth_middleware))
/// ```
///
/// Note: [`AuthState`] carries an `Option<Arc<KeyServer>>` field. `KeyServer`
/// is a PolyForm-Noncommercial Enterprise Edition type in upstream
/// `mcp-gateway` v2.11+; passing `None` keeps the request path on
/// MIT-licensed code only. A follow-up fork commit will split `AuthState`
/// so non-EE consumers do not even see the EE type in their dependency
/// graph.
pub fn with_auth<S>(router: Router<S>, state: AuthState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(middleware::from_fn_with_state(state, auth_middleware))
}

/// Wrap `router` with mcp-gateway's agent-JWT validation middleware
/// ([`agent_auth_middleware`]).
///
/// The wrapped router validates `Authorization: Bearer <agent-jwt>` against
/// the registered agents in [`AgentAuthState::registry`], populates
/// [`AgentIdentity`] in the request extensions, and emits audit events on
/// each request. Per-tool scope enforcement is **not** performed by the
/// middleware itself — handlers must call [`check_agent_scope_and_audit`]
/// with the resolved [`AgentIdentity`] before invoking a tool.
///
/// Equivalent to:
/// ```rust,ignore
/// router.layer(axum::middleware::from_fn_with_state(state, agent_auth_middleware))
/// ```
///
/// Setting [`AgentAuthState::enabled`] to `false` makes the middleware a
/// no-op pass-through; useful when a host wants the layer wired but
/// agent-JWT enforcement disabled via configuration.
pub fn with_agent_auth<S>(router: Router<S>, state: AgentAuthState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(middleware::from_fn_with_state(
        state,
        agent_auth_middleware,
    ))
}

// Compile-time spike confirming the re-exported middleware functions can be
// composed with `from_fn_with_state` and `Router::layer` in the upstream-style
// ordering (auth outer, agent_auth inner). Not invoked at runtime.
#[cfg(test)]
#[allow(dead_code)]
fn _layer_compose_compile_test(
    router: Router<()>,
    auth_state: AuthState,
    agent_auth_state: AgentAuthState,
) -> Router<()> {
    router
        .layer(middleware::from_fn_with_state(
            agent_auth_state,
            agent_auth_middleware,
        ))
        .layer(middleware::from_fn_with_state(auth_state, auth_middleware))
}
