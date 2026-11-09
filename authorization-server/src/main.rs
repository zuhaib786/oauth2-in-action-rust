//! The OAuth authorization server (http://localhost:9001).
//!
//! This is the server the project builds toward. In chapters 3 and 4 it's
//! given to you finished, so you can see how the client and protected resource
//! use it. In chapter 5 you build its endpoints yourself.
//!
//! Run it with:  cargo run -p authorization-server

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, LazyLock},
    time::{Duration, Instant},
};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, PRAGMA, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS},
    },
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use oauth_common::{
    Db, build_url, build_url_with_fragment, context, decode_client_credentials, param, random_string, render,
};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Mutex;
use tower_http::set_header::SetResponseHeaderLayer;
use url::{Host, Url};

// authorization server information
const AUTHORIZATION_ENDPOINT: &str = "http://localhost:9001/authorize";
const TOKEN_ENDPOINT: &str = "http://localhost:9001/token";

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

    fn has_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|registered| redirect_uri_matches(registered, redirect_uri))
    }
}

/// Redirect URIs must match exactly, with one exception: a native app's
/// loopback redirect URI may use any port, because the app only learns its
/// port when it starts (RFC 8252 §7.3).
fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    let (Ok(registered), Ok(mut requested)) = (Url::parse(registered), Url::parse(requested)) else {
        return false;
    };
    if registered.scheme() != "http" || !is_loopback_ip(&registered) {
        return false;
    }
    // Ignore the port; everything else must be the same.
    requested.set_port(registered.port()).is_ok() && requested == registered
}

/// The loopback IP literals. Not `localhost`: a name can resolve elsewhere
/// (RFC 8252 §8.3).
fn is_loopback_ip(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
        Some(Host::Ipv6(ip)) => ip == Ipv6Addr::LOCALHOST,
        _ => false,
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
            client_id: "oauth-native-client".into(),
            client_secret: None,
            redirect_uris: vec!["http://127.0.0.1/callback".into()],
            scope: "foo bar".into(),
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
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
const TOKEN_GRANT_TYPES: &[&str] = &["authorization_code", "refresh_token", "client_credentials", "password"];

// ---------------------------------------------------------------------------
// Users (resource owners)
// ---------------------------------------------------------------------------

/// Someone who can approve clients. The approval page simply asks which user
/// you are; only the password grant checks passwords.
#[derive(Clone, Debug, Serialize)]
struct User {
    sub: String,
    preferred_username: String,
    name: String,
    email: String,
    email_verified: bool,
    /// An Argon2id hash in PHC format, as a database would hold it. Never
    /// serialized, so it can't end up in a page or a response.
    #[serde(skip)]
    password_hash: String,
}

static USERS: LazyLock<Vec<User>> = LazyLock::new(|| {
    vec![
        User {
            sub: "9XE3-JI34-00132A".into(),
            preferred_username: "alice".into(),
            name: "Alice".into(),
            email: "alice.wonderland@example.com".into(),
            email_verified: true,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$zG2gnxnrgzuLxABrRRxn1w$qY9m21L9gRUHtwby7NWvn9EHVwUEEqExefJ0e22h7sI".into(),
        },
        User {
            sub: "1ZT5-OE63-57383B".into(),
            preferred_username: "bob".into(),
            name: "Bob".into(),
            email: "bob.loblob@example.net".into(),
            email_verified: false,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$USNNMw5hK+ilxKFjK8VmwQ$tNA37MDD4UfneGlg0eSuGyBTBEDZQjL4r/5w9RQfFQw".into(),
        },
        User {
            sub: "5UAL-CA03-60913C".into(),
            preferred_username: "carol".into(),
            name: "Carol".into(),
            email: "carol@example.org".into(),
            email_verified: true,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$GLluuuqw1akW95bjVRLkOw$YfuA5DRlSlvNlslQOwZZvzNtkjiDM1rU1vbnJX9ZyLM".into(),
        },
    ]
});

fn get_user(username: &str) -> Option<&'static User> {
    USERS.iter().find(|user| user.preferred_username == username)
}

/// Checked when the username is unknown, so that takes as long as a wrong
/// password and the response time doesn't say which usernames exist.
const DUMMY_PASSWORD_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$0eFanii02Ip3tLiUwqjjGQ$lZxOlwPFr0XHN2F8pobLuJzdFbnszgK3YO/ZoZbHzxM";

/// Checks a password against a PHC hash string. Argon2 is slow on purpose,
/// so this runs on a thread meant for blocking work, not on the async runtime.
async fn password_matches(hash: &'static str, password: String) -> bool {
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(hash)
            .is_ok_and(|hash| Argon2::default().verify_password(password.as_bytes(), &hash).is_ok())
    })
    .await
    .unwrap_or(false)
}

/// After this many failed password logins in a row, a username is locked.
const MAX_FAILED_LOGINS: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(60);

/// Recent failed password logins for one username.
#[derive(Default)]
struct FailedLogins {
    count: u32,
    locked_until: Option<Instant>,
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
    /// The password grant's brute-force guard, by username.
    failed_logins: HashMap<String, FailedLogins>,
}

impl ServerState {
    fn is_locked_out(&self, username: &str) -> bool {
        self.failed_logins
            .get(username)
            .and_then(|failures| failures.locked_until)
            .is_some_and(|until| Instant::now() < until)
    }

    fn record_login(&mut self, username: &str, succeeded: bool) {
        if succeeded {
            self.failed_logins.remove(username);
            return;
        }
        let failures = self.failed_logins.entry(username.to_string()).or_default();
        failures.count += 1;
        if failures.count >= MAX_FAILED_LOGINS {
            println!("Too many failed logins for {username}, locking it for {LOCKOUT:?}");
            failures.count = 0;
            failures.locked_until = Some(Instant::now() + LOCKOUT);
        }
    }
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
        let fragment = url::form_urlencoded::Serializer::new(String::new()).extend_pairs(&params).finish();
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

    if !client.has_redirect_uri(redirect_uri) {
        println!("Mismatched redirect URI, expected {:?} got {redirect_uri}", client.redirect_uris);
        return error_page("Invalid redirect URI");
    }

    // From here on the redirect URI is safe, so errors go back to the client.
    let Some(response_type) = ResponseType::parse(param(&query, "response_type")) else {
        return redirect_back(&query, None, &[("error", "unsupported_response_type")]);
    };

    if !client.allows_grant(response_type.grant_type()) {
        println!("Client {client_id} may not use the {} grant", response_type.grant_type());
        return redirect_back(&query, Some(response_type), &[("error", "unauthorized_client")]);
    }

    let rscope = split_scope(param(&query, "scope"));
    let cscope = split_scope(&client.scope);
    if has_extra_scope(&rscope, &cscope) {
        // client asked for a scope it couldn't have
        return redirect_back(&query, Some(response_type), &[("error", "invalid_scope")]);
    }

    let reqid = random_string(8);
    app.inner.lock().await.requests.insert(reqid.clone(), query.clone());

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
            state.codes.insert(code, CodeInfo { request: query, scope, user: user.preferred_username.clone() });
            response
        }
        Some(ResponseType::Token) => {
            // The implicit grant: the token goes straight back to the browser,
            // and never with a refresh token (RFC 6749 §4.2.2).
            let access_token = issue_access_token(&app.db, client, &scope, Some(&user.preferred_username));
            let scope = scope.join(" ");
            redirect_back(
                &query,
                response_type,
                &[("access_token", &access_token), ("token_type", "Bearer"), ("scope", &scope)],
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
    println!("Issuing access token {access_token} with scope {}", scope.join(" "));
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
    let basic = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(decode_client_credentials);
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
        println!("Client mismatch, expected {code_client_id} got {}", client.client_id);
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    let access_token = issue_access_token(&app.db, client, &code.scope, Some(&code.user));
    let refresh_token = issue_refresh_token(&app.db, client, &code.scope, Some(&code.user));
    println!("Issued tokens for code {code_value}");
    token_response(&access_token, Some(&refresh_token), &code.scope)
}

/// Creates a refresh token and saves it for later refresh_token grants.
fn issue_refresh_token(db: &Db, client: &Client, scope: &[String], user: Option<&str>) -> String {
    let refresh_token = random_string(32);
    db.insert(json!({
        "refresh_token": refresh_token,
        "client_id": client.client_id,
        "scope": scope,
        "user": user,
    }));
    println!("Issuing refresh token {refresh_token}");
    refresh_token
}

/// A successful token endpoint response (RFC 6749 §5.1).
fn token_response(access_token: &str, refresh_token: Option<&str>, scope: &[String]) -> Response {
    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "scope": scope.join(" "),
    });
    if let Some(refresh_token) = refresh_token {
        body["refresh_token"] = json!(refresh_token);
    }
    Json(body).into_response()
}

/// The scopes a grant without a user's approval page gets: the requested
/// ones if they're all allowed, every allowed one if none were requested,
/// or `None` if the client asked for one it may not have.
fn requested_scope(client: &Client, body: &HashMap<String, String>) -> Option<Vec<String>> {
    let cscope = split_scope(&client.scope);
    match body.get("scope") {
        Some(requested) => {
            let rscope = split_scope(requested);
            (!has_extra_scope(&rscope, &cscope)).then_some(rscope)
        }
        None => Some(cscope),
    }
}

/// grant_type=refresh_token: trade a refresh token for a new access token,
/// without bothering the user again.
fn refresh_token_grant(app: &AppState, client: &Client, body: &HashMap<String, String>) -> Response {
    let refresh_token = param(body, "refresh_token");

    let Some(token) = app.db.find_one(|doc| doc["refresh_token"] == refresh_token) else {
        println!("No matching token was found.");
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    println!("We found a matching refresh token: {refresh_token}");

    if token["client_id"] != client.client_id.as_str() {
        // Someone is using another client's refresh token. Revoke it.
        println!("Invalid client using a refresh token, expected {} got {}", token["client_id"], client.client_id);
        app.db.remove(|doc| doc["refresh_token"] == refresh_token);
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    let scope: Vec<String> = serde_json::from_value(token["scope"].clone()).unwrap_or_default();
    let access_token = issue_access_token(&app.db, client, &scope, token["user"].as_str());
    println!("for refresh token {refresh_token}");
    token_response(&access_token, Some(refresh_token), &scope)
}

/// grant_type=client_credentials: the client gets a token for itself. No
/// user is involved, so the token has none.
fn client_credentials_grant(app: &AppState, client: &Client, body: &HashMap<String, String>) -> Response {
    if client.client_secret.is_none() {
        // Anyone can send a public client's id, so it can't get tokens on its own (RFC 6749 §4.4).
        println!("Public client {} tried the client credentials grant", client.client_id);
        return json_error(StatusCode::BAD_REQUEST, "unauthorized_client");
    }

    let Some(scope) = requested_scope(client, body) else {
        println!("Client {} asked for scopes it may not have", client.client_id);
        return json_error(StatusCode::BAD_REQUEST, "invalid_scope");
    };

    // No refresh token: the client can just ask again (RFC 6749 §4.4.3).
    let access_token = issue_access_token(&app.db, client, &scope, None);
    token_response(&access_token, None, &scope)
}

/// grant_type=password: the client sends the user's own username and
/// password. Deprecated (RFC 9700 §2.4), and the reason this server has to
/// handle passwords at all.
async fn password_grant(app: &AppState, client: &Client, body: &HashMap<String, String>) -> Response {
    let username = param(body, "username");

    let Some(scope) = requested_scope(client, body) else {
        println!("Client {} asked for scopes it may not have", client.client_id);
        return json_error(StatusCode::BAD_REQUEST, "invalid_scope");
    };

    // RFC 6749 §4.3.2: "MUST protect the endpoint against brute force attacks"
    if app.inner.lock().await.is_locked_out(username) {
        println!("Refusing {username}: locked out after too many failed logins");
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    let user = get_user(username);
    let hash = user.map_or(DUMMY_PASSWORD_HASH, |user| user.password_hash.as_str());
    let password_ok = password_matches(hash, param(body, "password").to_string()).await;

    let user = user.filter(|_| password_ok);
    app.inner.lock().await.record_login(username, user.is_some());

    // The same answer for an unknown user and a wrong password.
    let Some(user) = user else {
        println!("Wrong username or password for {username}");
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };

    let access_token = issue_access_token(&app.db, client, &scope, Some(&user.preferred_username));
    let refresh_token = client
        .allows_grant("refresh_token")
        .then(|| issue_refresh_token(&app.db, client, &scope, Some(&user.preferred_username)));
    token_response(&access_token, refresh_token.as_deref(), &scope)
}

/// A layer that puts `name: value` on every response.
fn set_header(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(name, HeaderValue::from_static(value))
}

#[tokio::main]
async fn main() {
    oauth_common::set_views_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));

    let db = Db::shared();
    // clear the database on startup
    db.clear();

    let state = AppState { inner: Arc::default(), db };

    // A token response is a credential: no cache may keep it (RFC 6749 §5.1).
    let token_endpoint = Router::new()
        .route("/token", post(token))
        .layer(set_header(CACHE_CONTROL, "no-store"))
        .layer(set_header(PRAGMA, "no-cache"));

    let app = Router::new()
        .route("/", get(index))
        .route("/authorize", get(authorize))
        .route("/approve", post(approve))
        .merge(token_endpoint)
        // No other site may frame our pages and trick the user into clicking (RFC 6749 §10.13).
        .layer(set_header(X_FRAME_OPTIONS, "DENY"))
        .layer(set_header(CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"))
        .layer(set_header(X_CONTENT_TYPE_OPTIONS, "nosniff"))
        // The authorization request in our URLs stays out of Referer headers.
        .layer(set_header(REFERRER_POLICY, "no-referrer"))
        .with_state(state);

    oauth_common::serve(app, 9001, "OAuth Authorization Server").await;
}
