//! The OAuth authorization server (http://localhost:9001).
//!
//! This is the server the project builds toward. In chapters 3 and 4 it's
//! given to you finished, so you can see how the client and protected resource
//! use it. In chapter 5 you build its endpoints yourself.
//!
//!
//! EXERCISE 5-2 (book chapter 5): add refresh tokens.
//!   - issue a refresh token along with the access token
//!   - accept grant_type=refresh_token at the token endpoint
//! Compare with the solution:  git diff ch5-ex2-done -- authorization-server
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
use oauth_common::{
    Db, build_url, context, decode_client_credentials, param, random_string, render,
};
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
    USERS
        .iter()
        .find(|user| user.preferred_username == username)
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
    let client_id = param(&query, "client_id");
    let redirect_uri = param(&query, "redirect_uri");

    let Some(client) = get_client(client_id) else {
        println!("Unknown client {client_id}");
        return render("error", context! { error => "Unknown client" });
    };

    if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
        println!(
            "Mismatched redirect URI, expected {:?} got {redirect_uri}",
            client.redirect_uris
        );
        return render("error", context! { error => "Invalid redirect URI" });
    }

    let reqid = random_string(8);
    app.inner
        .lock()
        .await
        .requests
        .insert(reqid.clone(), query.clone());

    render(
        "approve",
        context! { client => client, reqid => reqid, users => &*USERS },
    )
}

/// The approval page's form posts here when the user clicks Approve or Deny.
async fn approve(
    State(app): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let mut state = app.inner.lock().await;

    let Some(query) = state.requests.remove(param(&form, "reqid")) else {
        // there was no matching saved request, this is an error
        return render(
            "error",
            context! { error => "No matching authorization request" },
        );
    };
    let redirect_uri = param(&query, "redirect_uri");

    if !form.contains_key("approve") {
        // user denied access
        return redirect_with_error(redirect_uri, "access_denied");
    }

    if param(&query, "response_type") != "code" {
        // we got a response type we don't understand
        return redirect_with_error(redirect_uri, "unsupported_response_type");
    }

    // user approved access
    let username = param(&form, "user");
    let Some(user) = get_user(username) else {
        println!("Unknown user {username}");
        return render(
            "error",
            context! { error => format!("Unknown user {username}") },
        );
    };

    let code = random_string(8);

    // The client must get back exactly the `state` it sent us.
    let mut params = vec![("code", code.as_str())];
    if let Some(client_state) = query.get("state") {
        params.push(("state", client_state));
    }
    let location = build_url(redirect_uri, &params);

    // save the code and request for later
    state.codes.insert(
        code.clone(),
        CodeInfo {
            request: query,
            scope: Vec::new(),
            user: user.preferred_username.clone(),
        },
    );

    Redirect::to(&location).into_response()
}

/// The token endpoint. The client calls this directly (not through the
/// browser) to trade a grant, like an authorization code, for an access token.
async fn token(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<HashMap<String, String>>,
) -> Response {
    // --- Who is calling? Authenticate the client. ---
    let mut client_id = None;
    let mut client_secret = None;

    // check the auth header
    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some((id, secret)) = decode_client_credentials(auth) {
            client_id = Some(id);
            client_secret = Some(secret);
        }
    }

    // otherwise, check the post body
    if let Some(id) = body.get("client_id") {
        if client_id.is_some() {
            // if we've already seen the client's credentials in the authorization header, this is an error
            println!("Client attempted to authenticate with multiple methods");
            return json_error(StatusCode::UNAUTHORIZED, "invalid_client");
        }
        client_id = Some(id.clone());
        client_secret = body.get("client_secret").cloned();
    }

    let client_id = client_id.unwrap_or_default();
    let Some(client) = get_client(&client_id) else {
        println!("Unknown client {client_id}");
        return json_error(StatusCode::UNAUTHORIZED, "invalid_client");
    };

    if client_secret.as_deref() != Some(client.client_secret.as_str()) {
        println!(
            "Mismatched client secret, expected {} got {client_secret:?}",
            client.client_secret
        );
        return json_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }

    // --- Which grant type is the client using? ---
    match param(&body, "grant_type") {
        "authorization_code" => authorization_code_grant(&app, client, &body).await,
        /*
         * TODO: Respond to a refresh token request by issuing a new access
         * token. Add a "refresh_token" arm here that calls a new function
         * (refresh_token_grant?) which:
         *   - finds the refresh token: app.db.find_one(|doc| doc["refresh_token"] == refresh_token)
         *     (not found → json_error(StatusCode::BAD_REQUEST, "invalid_grant"))
         *   - checks it belongs to this client. If not, someone stole it:
         *     delete it with app.db.remove(...) and answer invalid_grant
         *   - issues and saves a new access token for the same client and user
         *   - answers with the new access token and the same refresh token
         */
        "refresh_token" => refresh_token_grant(&app, client, &body),
        other => {
            println!("Unknown grant type {other}");
            json_error(StatusCode::BAD_REQUEST, "unsupported_grant_type")
        }
    }
}

fn refresh_token_grant(
    app: &AppState,
    client: &Client,
    body: &HashMap<String, String>,
) -> Response {
    let Some(refresh_token) = body.get("refresh_token") else {
        println!("Refresh token not set");
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let Some(doc) = app
        .db
        .find_one(|doc| &doc["refresh_token"] == refresh_token)
    else {
        println!("Invalid refresh token: {}", refresh_token);
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };

    // found the refresh token
    if doc["client_id"] != client.client_id {
        app.db.remove(|doc| &doc["refresh_token"] == refresh_token);
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    // refresh token belongs to the intended client
    let access_token = random_string(32);
    app.db.insert(json!({"client_id": client.client_id, "scope": doc["scope"], "access_token": access_token, "user": doc["user"]}));
    Json(
        json!({"access_token": access_token, "refresh_token": refresh_token, "token_type": "Bearer"})
        ).into_response()
}

/// grant_type=authorization_code: trade a code from /approve for a token.
async fn authorization_code_grant(
    app: &AppState,
    client: &Client,
    body: &HashMap<String, String>,
) -> Response {
    let code_value = param(body, "code");

    // `remove` both looks the code up and burns it, so it can only be used once
    let Some(code) = app.inner.lock().await.codes.remove(code_value) else {
        println!("Unknown code, {code_value}");
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };

    let code_client_id = param(&code.request, "client_id");
    if code_client_id != client.client_id {
        println!(
            "Client mismatch, expected {code_client_id} got {}",
            client.client_id
        );
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    let access_token = random_string(32);
    app.db.insert(json!({
        "access_token": access_token,
        "client_id": client.client_id,
        "scope": code.scope,
        "user": code.user,
    }));

    /*
     * TODO: Issue a refresh token alongside the access token, save it to the
     * database (like the access token, but under "refresh_token"), and put
     * it in the response.
     */

    let refresh_token = random_string(32);
    app.db.insert(
        json!({"refresh_token": &refresh_token, "client_id": client.client_id, "scope": code.scope, "user": code.user})
        );

    println!("Issuing access token {access_token}");
    println!("Issued tokens for code {code_value}");

    Json(json!({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
    }))
    .into_response()
}

#[tokio::main]
async fn main() {
    oauth_common::set_views_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));

    let db = Db::shared();
    // clear the database on startup
    db.clear();

    let state = AppState {
        inner: Arc::default(),
        db,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/authorize", get(authorize))
        .route("/approve", post(approve))
        .route("/token", post(token))
        .with_state(state);

    oauth_common::serve(app, 9001, "OAuth Authorization Server").await;
}
