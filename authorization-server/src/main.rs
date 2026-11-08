//! The OAuth authorization server (http://localhost:9001).
//!
//! This is the server the project builds toward. In chapters 3 and 4 it's
//! given to you finished, so you can see how the client and protected resource
//! use it. In chapter 5 you build its endpoints yourself.
//!
//!
//! EXERCISE 5-1 (book chapter 5): build the authorization server's three
//! endpoints, /authorize, /approve and /token, for the authorization code
//! grant. Each has a TODO with steps. The helpers above them do the fiddly
//! parts. Until 5-3 adds scopes, the client's Words/Produce/Favorites
//! pages won't work, because tokens have no scopes.
//! Compare with the solution:  git diff ch5-ex1-done -- authorization-server
//!
//! Run it with:  cargo run -p authorization-server

// Some helpers aren't used until a later exercise. This silences the
// "unused" warnings until then.
#![allow(unused)]

use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
};

use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use oauth_common::{Db, build_url, context, decode_client_credentials, param, random_string, render};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

// authorization server information
const AUTHORIZATION_ENDPOINT: &str = "http://localhost:9001/authorize";
const TOKEN_ENDPOINT: &str = "http://localhost:9001/token";

// ---------------------------------------------------------------------------
// Registered clients
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
struct Client {
    client_id: String,
    client_secret: String,
    redirect_uris: Vec<String>,
    /// The scopes this client may ask for, separated by spaces.
    scope: String,
}

static CLIENTS: LazyLock<Vec<Client>> = LazyLock::new(|| {
    vec![Client {
        client_id: "oauth-client-1".into(),
        client_secret: "oauth-client-secret-1".into(),
        redirect_uris: vec!["http://localhost:9000/callback".into()],
        scope: "foo bar read write delete fruit veggies meats movies foods music".into(),
    }]
});

fn get_client(client_id: &str) -> Option<&'static Client> {
    CLIENTS.iter().find(|client| client.client_id == client_id)
}

// ---------------------------------------------------------------------------
// Users (resource owners)
// ---------------------------------------------------------------------------

/// Someone who can approve clients. There are no passwords yet: the approval
/// page simply asks which user you are.
#[derive(Clone, Debug, Serialize)]
struct User {
    sub: String,
    preferred_username: String,
    name: String,
    email: String,
    email_verified: bool,
}

static USERS: LazyLock<Vec<User>> = LazyLock::new(|| {
    vec![
        User {
            sub: "9XE3-JI34-00132A".into(),
            preferred_username: "alice".into(),
            name: "Alice".into(),
            email: "alice.wonderland@example.com".into(),
            email_verified: true,
        },
        User {
            sub: "1ZT5-OE63-57383B".into(),
            preferred_username: "bob".into(),
            name: "Bob".into(),
            email: "bob.loblob@example.net".into(),
            email_verified: false,
        },
    ]
});

fn get_user(username: &str) -> Option<&'static User> {
    USERS.iter().find(|user| user.preferred_username == username)
}

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

/// What we remember about an authorization code until the client trades it
/// in at the token endpoint.
struct CodeInfo {
    /// The query parameters of the original /authorize request.
    request: HashMap<String, String>,
    /// The scopes the user approved.
    scope: Vec<String>,
    /// Who approved it (their `preferred_username`).
    user: String,
}

/// The JS keeps these in global variables (`var codes = {}` and
/// `var requests = {}`). Rust makes us put shared, changing data behind a
/// lock, so every handler gets a handle to it through `State`.
#[derive(Default)]
struct ServerState {
    /// Authorization codes we've handed out and not yet seen at /token.
    codes: HashMap<String, CodeInfo>,
    /// /authorize requests waiting for the user to click Approve or Deny,
    /// keyed by a random request id that goes into the approval form.
    requests: HashMap<String, HashMap<String, String>>,
}

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<ServerState>>,
    /// Issued tokens. The protected resource reads the same file.
    db: Db,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Splits "foo bar" into ["foo", "bar"].
fn split_scope(scope: &str) -> Vec<String> {
    scope.split_whitespace().map(String::from).collect()
}

/// True if `requested` contains a scope that is not in `allowed`
/// (`__.difference(rscope, cscope).length > 0` in the JS).
fn has_extra_scope(requested: &[String], allowed: &[String]) -> bool {
    requested.iter().any(|s| !allowed.contains(s))
}

/// Each ticked scope checkbox on the approval page arrives as a form field
/// named "scope_<name>". Returns the <name> parts, sorted.
fn scopes_from_form(form: &HashMap<String, String>) -> Vec<String> {
    let mut scopes: Vec<String> = form
        .keys()
        .filter_map(|key| key.strip_prefix("scope_"))
        .map(String::from)
        .collect();
    scopes.sort(); // a HashMap's keys come out in random order
    scopes
}

/// Sends the browser back to the client's redirect URI with `?error=...`.
fn redirect_with_error(redirect_uri: &str, error: &str) -> Response {
    Redirect::to(&build_url(redirect_uri, &[("error", error)])).into_response()
}

/// A JSON error response from the token endpoint, e.g. `{"error": "invalid_grant"}`.
fn json_error(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

async fn index() -> Response {
    render(
        "index",
        context! {
            clients => &*CLIENTS,
            auth_server => context! {
                authorization_endpoint => AUTHORIZATION_ENDPOINT,
                token_endpoint => TOKEN_ENDPOINT,
            },
        },
    )
}

/// The authorization endpoint. The client sends the user's browser here.
async fn authorize(
    State(app): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    /*
     * TODO: Process the request, validate the client, and send the user to
     * the approval page.
     *
     * Steps:
     *   1. Look up the client: get_client(param(&query, "client_id")).
     *      Unknown → render("error", context! { error => "Unknown client" })
     *   2. The "redirect_uri" must be one of client.redirect_uris. If not,
     *      show an error page ("Invalid redirect URI"). Don't redirect to
     *      it: it could be an attacker's site!
     *   3. Remember the request for /approve: put `query.clone()` into
     *      app.inner.lock().await.requests under a new id, random_string(8)
     *   4. render("approve", context! { client => client, reqid => reqid, users => &*USERS })
     */

    render("error", context! { error => "TODO: implement /authorize in authorization-server/src/main.rs" })
}

/// The approval page's form posts here when the user clicks Approve or Deny.
async fn approve(
    State(app): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    /*
     * TODO: Process the results of the approval page, authorize the client.
     *
     * Steps:
     *   1. Take the saved request out of state.requests using the form's
     *      "reqid" (`remove` gets it and deletes it in one go).
     *      Not found → error page "No matching authorization request"
     *   2. The user clicked Deny if the form has no "approve" field. Then:
     *      redirect_with_error(redirect_uri, "access_denied")
     *   3. If the request's response_type isn't "code":
     *      redirect_with_error(redirect_uri, "unsupported_response_type")
     *   4. Find the user they picked: get_user(param(&form, "user"))
     *   5. Make a code, random_string(8), and save a CodeInfo for it in
     *      state.codes (use `scope: Vec::new()` for now; scopes come in 5-3)
     *   6. Redirect to redirect_uri with ?code=...&state=... using
     *      build_url(...). Send back the client's `state` exactly as it
     *      sent it, if it sent one.
     */

    render("error", context! { error => "TODO: implement /approve in authorization-server/src/main.rs" })
}

/// The token endpoint. The client calls this directly (not through the
/// browser) to trade a grant, like an authorization code, for an access token.
async fn token(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<HashMap<String, String>>,
) -> Response {
    /*
     * TODO: Process the request, issue an access token.
     *
     * Steps:
     *   1. Authenticate the client. Its id and secret come either in the
     *      Authorization header (decode_client_credentials(...) reads it)
     *      or as client_id and client_secret in the form body, but not both.
     *      Any problem → json_error(StatusCode::UNAUTHORIZED, "invalid_client")
     *   2. grant_type must be "authorization_code". If not:
     *      json_error(StatusCode::BAD_REQUEST, "unsupported_grant_type")
     *   3. Take the code out of state.codes so it can't be used twice. It
     *      must exist and belong to this client. If not:
     *      json_error(StatusCode::BAD_REQUEST, "invalid_grant")
     *   4. Make an access token, random_string(32), and save it so the
     *      protected resource can find it:
     *          app.db.insert(json!({ "access_token": ..., "client_id": ..., "scope": ..., "user": ... }))
     *   5. Answer: Json(json!({ "access_token": ..., "token_type": "Bearer" })).into_response()
     *
     * Tip: a separate `async fn authorization_code_grant(...)` for steps 3-5
     * keeps this tidy, and gives later grant types an obvious place to go.
     */

    json_error(StatusCode::NOT_IMPLEMENTED, "TODO: implement /token")
}

#[tokio::main]
async fn main() {
    oauth_common::set_views_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));

    let db = Db::shared();
    // clear the database on startup
    db.clear();

    let state = AppState { inner: Arc::default(), db };

    let app = Router::new()
        .route("/", get(index))
        .route("/authorize", get(authorize))
        .route("/approve", post(approve))
        .route("/token", post(token))
        .with_state(state);

    oauth_common::serve(app, 9001, "OAuth Authorization Server").await;
}
