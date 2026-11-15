//! The OAuth authorization server (http://localhost:9001).
//!
//! This is the server the project builds toward. In chapters 3 and 4 it's
//! given to you finished, so you can see how the client and protected resource
//! use it. In chapter 5 you build its endpoints yourself.
//!
//! Run it with:  cargo run -p authorization-server

use argon2::{
    Argon2,
    password_hash::{PasswordVerifier, phc::PasswordHash},
};
use std::time::{Duration, Instant};
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
    Db, build_url, build_url_with_fragment, context, decode_client_credentials, param,
    random_string, render,
};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

// authorization server information
const AUTHORIZATION_ENDPOINT: &str = "http://localhost:9001/authorize";
const TOKEN_ENDPOINT: &str = "http://localhost:9001/token";
/// Unknown usernames are checked against this, so they take as long to refuse
/// as a wrong password (R8). Nobody's password hashes to it.
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$tl705c4A+SbC7JiFG5eNeA$DYwcRFuBNlLdpGU4suXsB3kbyxA11OdmCI6nc0uLbmQ";

// ---------------------------------------------------------------------------
// Registered clients
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize)]
struct Client {
    client_id: String,
    /// `None` for a public client: one that can't keep a secret, like an app
    /// running in a browser.
    client_secret: Option<String>,
    redirect_uris: Vec<String>,
    /// The scopes this client may ask for, separated by spaces.
    scope: String,
    /// The grant types this client may use (RFC 7591 §2).
    grant_types: Vec<String>,
}

impl Client {
    fn allows_grant(&self, grant_type: &str) -> bool {
        self.grant_types.iter().any(|g| g == grant_type)
    }
}

static CLIENTS: LazyLock<Vec<Client>> = LazyLock::new(|| {
    vec![
        Client {
            client_id: "oauth-client-1".into(),
            client_secret: Some("oauth-client-secret-1".into()),
            redirect_uris: vec!["http://localhost:9000/callback".into()],
            scope: "foo bar read write delete fruit veggies meats movies foods music".into(),
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        },
        Client {
            client_id: "oauth-client-implicit".into(),
            client_secret: None,
            redirect_uris: vec!["http://localhost:9000/implicit".into()],
            scope: "foo bar".into(),
            grant_types: vec!["implicit".into()],
        },
        Client {
            client_id: "oauth-client-service".into(),
            client_secret: Some("oauth-client-secret-service".into()),
            redirect_uris: vec![],
            scope: "read write".into(),
            grant_types: vec!["client_credentials".into()],
        },
        Client {
            client_id: "oauth-client-trusted".into(),
            client_secret: Some("oauth-client-secret-trusted".into()),
            redirect_uris: vec![],
            scope: "foo bar read write".into(),
            grant_types: vec!["password".into(), "refresh_token".into()],
        },
    ]
});

fn get_client(client_id: &str) -> Option<&'static Client> {
    CLIENTS.iter().find(|client| client.client_id == client_id)
}

/// What the client asks /authorize for.
#[derive(Clone, Copy, PartialEq)]
enum ResponseType {
    /// An authorization code, sent back in the query.
    Code,
    /// An access token, sent back in the fragment (the implicit grant).
    Token,
}

impl ResponseType {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "code" => Some(Self::Code),
            "token" => Some(Self::Token),
            _ => None,
        }
    }

    /// The grant type a client must be registered for to use this.
    fn grant_type(self) -> &'static str {
        match self {
            Self::Code => "authorization_code",
            Self::Token => "implicit",
        }
    }
}

/// The grant types the token endpoint knows.
const TOKEN_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "password",
];

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
    #[serde(skip_serializing)]
    /// An Argon2id PHC string (`$argon2id$v=19$...`), salt included. Never
    /// the password itself (R2), and never serialized (R3).
    password_hash: String,
}

/// True if `password` hashes to `hash`. Slow on purpose: call it from
/// `spawn_blocking`.
fn password_matches(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

static USERS: LazyLock<Vec<User>> = LazyLock::new(|| {
    vec![
        User {
            sub: "9XE3-JI34-00132A".into(),
            preferred_username: "alice".into(),
            name: "Alice".into(),
            email: "alice.wonderland@example.com".into(),
            email_verified: true,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$UclJKwEyUn735zaUxCP4Sw$m1iek+iqJ/W8SYtbpByOCFgoWGGMJncrVlUV5UiqwTA".into(),
        },
        User {
            sub: "1ZT5-OE63-57383B".into(),
            preferred_username: "bob".into(),
            name: "Bob".into(),
            email: "bob.loblob@example.net".into(),
            email_verified: false,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$tvuKIhSDHDmydiX1MCFlgw$oE83RUVbX308Hy2oXcpgBpeDmv17CMg77eeQFDJDchQ".into(),
        },
        User {
            sub: "5UAL-CA03-60913C".into(),
            preferred_username: "carol".into(),
            name: "Carol".into(),
            email: "carol@example.org".into(),
            email_verified: true,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$WCtIHY9XlIlNOtpcB9ZZLA$oOBm3jNYvCi1Wut6Ue+tEq6Ves0ktOM7/UFqPxpo5nk".into(),
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

#[derive(Default)]
struct Attempts {
    /// Failures in a row, counting attempts still being checked.
    failures: u32,
    /// Set once `failures` reaches the limit.
    locked_until: Option<Instant>,
}

/// R9: 5 failed logins in a row lock a username out for 60 seconds.
#[derive(Default)]
struct LoginGuard {
    /// Keyed by the username as typed, known or not, so the lockout doesn't
    /// tell anyone which usernames exist.
    by_username: HashMap<String, Attempts>,
}

impl LoginGuard {
    const MAX_FAILURES: u32 = 5;
    const LOCKOUT: Duration = Duration::from_secs(60);

    /// Call before checking the password; false means refuse without checking.
    /// The attempt counts as a failure until `succeeded` says otherwise, so
    /// many guesses sent at once can't all slip past the limit.
    fn begin(&mut self, username: &str, now: Instant) -> bool {
        let attempts = self.by_username.entry(username.to_owned()).or_default();
        if let Some(until) = attempts.locked_until {
            if now < until {
                return false;
            }
            *attempts = Attempts::default();
        }
        attempts.failures += 1;
        if attempts.failures >= Self::MAX_FAILURES {
            attempts.locked_until = Some(now + Self::LOCKOUT);
        }
        true
    }

    fn succeeded(&mut self, username: &str) {
        self.by_username.remove(username);
    }
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
    /// Failed password logins. Its own lock, so logins don't wait on `inner`.
    login_guard: Arc<Mutex<LoginGuard>>,
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

/// Sends the browser back to the client's redirect URI with `params`, plus
/// the request's `state` if it had one. The implicit grant answers in the
/// fragment, everything else in the query.
fn redirect_back(
    request: &HashMap<String, String>,
    response_type: Option<ResponseType>,
    params: &[(&str, &str)],
) -> Response {
    let redirect_uri = param(request, "redirect_uri");
    let mut params = params.to_vec();
    if let Some(state) = request.get("state") {
        params.push(("state", state));
    }

    let location = if response_type == Some(ResponseType::Token) {
        let fragment = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&params)
            .finish();
        build_url_with_fragment(redirect_uri, &[], &fragment)
    } else {
        build_url(redirect_uri, &params)
    };
    Redirect::to(&location).into_response()
}

/// The error page, for errors we can't send back to the client.
fn error_page(error: &str) -> Response {
    let mut page = render("error", context! { error => error });
    *page.status_mut() = StatusCode::BAD_REQUEST;
    page
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
        return error_page("Unknown client");
    };

    if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
        println!(
            "Mismatched redirect URI, expected {:?} got {redirect_uri}",
            client.redirect_uris
        );
        return error_page("Invalid redirect URI");
    }

    // From here on the redirect URI is safe, so errors go back to the client.
    let Some(response_type) = ResponseType::parse(param(&query, "response_type")) else {
        return redirect_back(&query, None, &[("error", "unsupported_response_type")]);
    };

    if !client.allows_grant(response_type.grant_type()) {
        println!(
            "Client {client_id} may not use the {} grant",
            response_type.grant_type()
        );
        return redirect_back(
            &query,
            Some(response_type),
            &[("error", "unauthorized_client")],
        );
    }

    let rscope = split_scope(param(&query, "scope"));
    let cscope = split_scope(&client.scope);
    if has_extra_scope(&rscope, &cscope) {
        // client asked for a scope it couldn't have
        return redirect_back(&query, Some(response_type), &[("error", "invalid_scope")]);
    }

    let reqid = random_string(8);
    app.inner
        .lock()
        .await
        .requests
        .insert(reqid.clone(), query.clone());

    render(
        "approve",
        context! { client => client, reqid => reqid, scope => rscope, users => &*USERS },
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
        return error_page("No matching authorization request");
    };
    let response_type = ResponseType::parse(param(&query, "response_type"));

    if !form.contains_key("approve") {
        // user denied access
        return redirect_back(&query, response_type, &[("error", "access_denied")]);
    }

    // user approved access
    let username = param(&form, "user");
    let Some(user) = get_user(username) else {
        println!("Unknown user {username}");
        return error_page(&format!("Unknown user {username}"));
    };

    let scope = scopes_from_form(&form);
    let client = get_client(param(&query, "client_id")).expect("client was checked in /authorize");
    if has_extra_scope(&scope, &split_scope(&client.scope)) {
        // client asked for a scope it couldn't have
        return redirect_back(&query, response_type, &[("error", "invalid_scope")]);
    }

    match response_type {
        Some(ResponseType::Code) => {
            let code = random_string(8);
            let response = redirect_back(&query, response_type, &[("code", &code)]);
            // save the code and request for later
            state.codes.insert(
                code,
                CodeInfo {
                    request: query,
                    scope,
                    user: user.preferred_username.clone(),
                },
            );
            response
        }
        Some(ResponseType::Token) => {
            // The implicit grant: the token goes straight back to the browser,
            // and never with a refresh token (RFC 6749 §4.2.2).
            let access_token =
                issue_access_token(&app.db, client, &scope, Some(&user.preferred_username));
            let scope = scope.join(" ");
            redirect_back(
                &query,
                response_type,
                &[
                    ("access_token", &access_token),
                    ("token_type", "Bearer"),
                    ("scope", &scope),
                ],
            )
        }
        None => unreachable!("/authorize only saves requests with a known response_type"),
    }
}

/// Creates an access token and saves it for the protected resource.
fn issue_access_token(db: &Db, client: &Client, scope: &[String], user: Option<&str>) -> String {
    let access_token = random_string(32);
    db.insert(json!({
        "access_token": access_token,
        "client_id": client.client_id,
        "scope": scope,
        "user": user,
    }));
    println!(
        "Issuing access token {access_token} with scope {}",
        scope.join(" ")
    );
    access_token
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
    let basic = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(decode_client_credentials);
    if let Some((id, secret)) = basic {
        client_id = Some(id);
        client_secret = Some(secret);
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

    let authenticated = match (&client.client_secret, &client_secret) {
        // a confidential client must prove it knows its secret
        (Some(expected), Some(given)) => expected == given,
        // a public client has no secret to prove: its client_id is all we get
        (None, None) => true,
        _ => false,
    };
    if !authenticated {
        println!("Client {client_id} failed to authenticate");
        return json_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }

    // --- Which grant type is the client using, and may it? ---
    let grant_type = param(&body, "grant_type");
    if !TOKEN_GRANT_TYPES.contains(&grant_type) {
        println!("Unknown grant type {grant_type}");
        return json_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    if !client.allows_grant(grant_type) {
        println!("Client {client_id} may not use the {grant_type} grant");
        return json_error(StatusCode::BAD_REQUEST, "unauthorized_client");
    }

    match grant_type {
        "authorization_code" => authorization_code_grant(&app, client, &body).await,
        "refresh_token" => refresh_token_grant(&app, client, &body),
        "client_credentials" => client_credentials_grant(&app, client, &body),
        "password" => password_grant(&app, client, &body).await,
        _ => unreachable!("checked against TOKEN_GRANT_TYPES"),
    }
}

/// grant_type=password: the client sends the user's own username and
/// password (RFC 6749 §4.3). An unknown username and a wrong password get the
/// same answer (R7) after the same work (R8).
async fn password_grant(
    app: &AppState,
    client: &Client,
    body: &HashMap<String, String>,
) -> Response {
    let (Some(username), Some(password)) = (body.get("username"), body.get("password")) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request");
    };

    // A bad scope is a broken request, not a guess: refuse it before
    // counting an attempt or spending a hash on it.
    let cscope = split_scope(&client.scope);
    let scope = match body.get("scope") {
        Some(requested) => split_scope(requested),
        None => cscope.clone(),
    };
    if has_extra_scope(&scope, &cscope) {
        println!(
            "Client {} asked for scopes it may not have: {scope:?}",
            client.client_id
        );
        return json_error(StatusCode::BAD_REQUEST, "invalid_scope");
    }

    if !app.login_guard.lock().await.begin(username, Instant::now()) {
        println!("Refused a password login: too many failures for that username");
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    // Known or not, every username costs one Argon2 check (R8).
    let user = get_user(username);
    let hash = user.map_or(DUMMY_PASSWORD_HASH, |u| u.password_hash.as_str());
    let password = password.clone();
    let verified = tokio::task::spawn_blocking(move || password_matches(hash, &password))
        .await
        .unwrap_or(false);

    let Some(user) = user.filter(|_| verified) else {
        // No username in the log: people sometimes type their password there (R3).
        println!("Refused a password login: wrong username or password");
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    app.login_guard.lock().await.succeeded(username);

    println!(
        "{} logged in with the password grant",
        user.preferred_username
    );
    issue_tokens(&app.db, client, &scope, &user.preferred_username)
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

    println!("Trading in code {code_value}");
    issue_tokens(&app.db, client, &code.scope, &code.user)
}

/// Issues an access token and a refresh token for `user`, and builds the
/// token endpoint's answer.
fn issue_tokens(db: &Db, client: &Client, scope: &[String], user: &str) -> Response {
    let access_token = issue_access_token(db, client, scope, Some(user));
    let refresh_token = random_string(32);
    db.insert(json!({
        "refresh_token": refresh_token,
        "client_id": client.client_id,
        "scope": scope,
        "user": user,
    }));
    println!("and refresh token {refresh_token}");

    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "refresh_token": refresh_token,
        "scope": scope.join(" "),
    }))
    .into_response()
}

/// grant_type=refresh_token: trade a refresh token for a new access token,
/// without bothering the user again.
fn refresh_token_grant(
    app: &AppState,
    client: &Client,
    body: &HashMap<String, String>,
) -> Response {
    let refresh_token = param(body, "refresh_token");

    let Some(token) = app.db.find_one(|doc| doc["refresh_token"] == refresh_token) else {
        println!("No matching token was found.");
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    println!("We found a matching refresh token: {refresh_token}");

    if token["client_id"] != client.client_id.as_str() {
        // Someone is using another client's refresh token. Revoke it.
        println!(
            "Invalid client using a refresh token, expected {} got {}",
            token["client_id"], client.client_id
        );
        app.db.remove(|doc| doc["refresh_token"] == refresh_token);
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    let access_token = random_string(32);
    app.db.insert(json!({
        "access_token": access_token,
        "client_id": client.client_id,
        "scope": token["scope"],
        "user": token["user"],
    }));
    println!("Issuing access token {access_token} for refresh token {refresh_token}");

    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "refresh_token": refresh_token,
        "scope": scope_to_string(&token["scope"]),
    }))
    .into_response()
}

/// grant_type=client_credentials: the client gets a token for itself. No
/// user is involved, so the token has none.
fn client_credentials_grant(
    app: &AppState,
    client: &Client,
    body: &HashMap<String, String>,
) -> Response {
    if client.client_secret.is_none() {
        // Anyone can send a public client's id, so it can't get tokens on its own (RFC 6749 §4.4).
        println!(
            "Public client {} tried the client credentials grant",
            client.client_id
        );
        return json_error(StatusCode::BAD_REQUEST, "unauthorized_client");
    }

    let cscope = split_scope(&client.scope);
    let scope = match body.get("scope") {
        Some(requested) => split_scope(requested),
        None => cscope.clone(),
    };
    if has_extra_scope(&scope, &cscope) {
        println!(
            "Client {} asked for scopes it may not have: {scope:?}",
            client.client_id
        );
        return json_error(StatusCode::BAD_REQUEST, "invalid_scope");
    }

    // No refresh token: the client can just ask again (RFC 6749 §4.4.3).
    let access_token = issue_access_token(&app.db, client, &scope, None);
    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "scope": scope.join(" "),
    }))
    .into_response()
}

/// Turns a scope list stored in the database (`["foo", "bar"]`) back into
/// the space-separated string OAuth uses on the wire (`"foo bar"`).
fn scope_to_string(scope: &Value) -> String {
    scope
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
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
        login_guard: Arc::default(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/authorize", get(authorize))
        .route("/approve", post(approve))
        .route("/token", post(token))
        .with_state(state);

    oauth_common::serve(app, 9001, "OAuth Authorization Server").await;
}
