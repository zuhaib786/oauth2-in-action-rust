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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, WWW_AUTHENTICATE, PRAGMA, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
            X_FRAME_OPTIONS,
        },
    },
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, jwk::JwkSet};
use oauth_common::{
    Db, build_url, build_url_with_fragment, context, decode_client_credentials, param, pkce_challenge, random_string,
    render,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;
use tower_http::set_header::SetResponseHeaderLayer;
use url::{Host, Url};

// authorization server information
const AUTHORIZATION_ENDPOINT: &str = "http://localhost:9001/authorize";
const TOKEN_ENDPOINT: &str = "http://localhost:9001/token";

/// The `iss` of every token we issue.
const ISSUER: &str = "http://localhost:9001/";
/// The `aud` of our access tokens: the protected resource they're for.
const PROTECTED_RESOURCE: &str = "http://localhost:9002/";
/// Seconds an access token stays good. Short, because a self-contained token
/// can't be called back once it's out.
const ACCESS_TOKEN_LIFETIME: u64 = 300;

/// The public half of our signing key, as a JWK Set, served at /jwks. Made
/// once from the private key: `n` from `openssl rsa -in keys/signing-key.pem
/// -noout -modulus`, and the `kid` is the key's RFC 7638 thumbprint.
const JWKS: &str = include_str!("../keys/jwks.json");

/// Signs access tokens (RS256). Only we have it.
static SIGNING_KEY: LazyLock<EncodingKey> = LazyLock::new(|| {
    EncodingKey::from_rsa_pem(include_bytes!("../keys/signing-key.pem")).expect("keys/signing-key.pem is an RSA key")
});

/// The `kid` of the signing key, as published in the JWK Set.
static SIGNING_KEY_ID: LazyLock<String> = LazyLock::new(|| {
    let jwks: Value = serde_json::from_str(JWKS).expect("keys/jwks.json is JSON");
    jwks["keys"][0]["kid"].as_str().expect("keys/jwks.json has a kid").to_string()
});

/// Checks our own signatures, for introspection.
static VERIFYING_KEY: LazyLock<DecodingKey> = LazyLock::new(|| {
    let jwks: JwkSet = serde_json::from_str(JWKS).expect("keys/jwks.json is a JWK Set");
    DecodingKey::from_jwk(&jwks.keys[0]).expect("keys/jwks.json holds an RSA key")
});

// ---------------------------------------------------------------------------
// Protected resources
// ---------------------------------------------------------------------------

/// A protected resource that may introspect the tokens meant for it.
struct ProtectedResource {
    resource_id: &'static str,
    resource_secret: &'static str,
    /// The `aud` of the tokens it's allowed to hear about.
    audience: &'static str,
}

const PROTECTED_RESOURCES: &[ProtectedResource] = &[
    ProtectedResource {
        resource_id: "protected-resource-1",
        resource_secret: "protected-resource-secret-1",
        audience: PROTECTED_RESOURCE,
    },
    ProtectedResource {
        resource_id: "protected-resource-2",
        resource_secret: "protected-resource-secret-2",
        audience: "http://localhost:9003/",
    },
];

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

/// What we remember about an authorization code.
struct CodeInfo {
    /// The query parameters of the original /authorize request.
    request: HashMap<String, String>,
    /// The scopes the user approved.
    scope: Vec<String>,
    /// Who approved it (their `preferred_username`).
    user: String,
    /// The grant that the tokens from this code belong to.
    grant_id: String,
    issued_at: Instant,
    /// Set the first time the code is presented. Used codes are kept, so a
    /// second use is recognised as a replay rather than an unknown code.
    used: bool,
}

/// How long a code may wait to be traded in (RFC 6749 §4.1.2: 10 minutes at most).
const CODE_LIFETIME: Duration = Duration::from_secs(60);

/// One approval: a user (or nobody, for client credentials) letting one
/// client use some scopes. Every token issued under a grant records its id,
/// so the whole family can be revoked at once.
struct Grant<'a> {
    id: String,
    client: &'a Client,
    scope: Vec<String>,
    user: Option<String>,
}

impl<'a> Grant<'a> {
    fn new(client: &'a Client, scope: Vec<String>, user: Option<String>) -> Self {
        Grant { id: random_string(32), client, scope, user }
    }

    /// Who the token is about: the user's `sub`, or for client credentials
    /// (no user) the client itself.
    fn subject(&self) -> &str {
        match self.user.as_deref().and_then(get_user) {
            Some(user) => &user.sub,
            None => &self.client.client_id,
        }
    }

    /// Creates an access token: a JWT the protected resource can check on its
    /// own. A record of it is kept as well, by `jti`.
    fn issue_access_token(&self, db: &Db) -> String {
        let iat = now_secs();
        let jti = random_string(32);
        let claims = json!({
            "iss": ISSUER,
            "sub": self.subject(),
            "aud": PROTECTED_RESOURCE,
            "client_id": self.client.client_id,
            "scope": self.scope.join(" "),
            "iat": iat,
            "exp": iat + ACCESS_TOKEN_LIFETIME,
            "jti": jti,
        });
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("at+jwt".into());
        header.kid = Some(SIGNING_KEY_ID.clone());
        let access_token = jsonwebtoken::encode(&header, &claims, &SIGNING_KEY).expect("signing with RS256 doesn't fail");
        db.insert(json!({
            "jti": jti,
            "client_id": self.client.client_id,
            "scope": self.scope,
            "user": self.user,
            "grant_id": self.id,
        }));
        println!("Issuing access token {access_token} with scope {}", self.scope.join(" "));
        access_token
    }

    /// Creates a refresh token and saves it for later refresh_token grants.
    fn issue_refresh_token(&self, db: &Db) -> String {
        let refresh_token = random_string(32);
        db.insert(json!({
            "refresh_token": refresh_token,
            "client_id": self.client.client_id,
            "scope": self.scope,
            "user": self.user,
            "grant_id": self.id,
        }));
        println!("Issuing refresh token {refresh_token}");
        refresh_token
    }
}

/// Seconds since 1970: the unit of `iat` and `exp`.
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The claims of one of our access tokens, if the signature and the claims
/// check out. Says nothing about whether it was revoked.
fn verify_access_token(token: &str) -> Option<Map<String, Value>> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if header.typ.as_deref() != Some("at+jwt") || header.kid.as_deref() != Some(SIGNING_KEY_ID.as_str()) {
        return None;
    }
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    // which audience is fine depends on who's asking
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "jti"]);
    jsonwebtoken::decode(token, &VERIFYING_KEY, &validation).ok().map(|token| token.claims)
}

/// Deletes every token issued under a grant.
fn revoke_grant(db: &Db, grant_id: &str) {
    let revoked = db.remove(|doc| doc["grant_id"] == grant_id);
    println!("Revoked {revoked} tokens of grant {grant_id}");
}

/// The JS keeps these in global variables (`var codes = {}` and
/// `var requests = {}`). Rust makes us put shared, changing data behind a
/// lock, so every handler gets a handle to it through `State`.
#[derive(Default)]
struct ServerState {
    /// Authorization codes we've handed out, used or not.
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

/// The parameters as a map, or `None` if any of them appears more than once.
/// "Request and response parameters MUST NOT be included more than once"
/// (RFC 6749 §3.1, §3.2): if they were, two pieces of code could each read
/// a different one.
fn single_valued(pairs: Vec<(String, String)>) -> Option<HashMap<String, String>> {
    let mut params = HashMap::with_capacity(pairs.len());
    for (key, value) in pairs {
        if params.insert(key, value).is_some() {
            return None;
        }
    }
    Some(params)
}

/// What S256 produces: 43 characters of base64url.
fn is_valid_challenge(challenge: &str) -> bool {
    challenge.len() == 43 && challenge.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// 43 to 128 characters of `A-Z a-z 0-9 - . _ ~` (RFC 7636 §4.1).
fn is_valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
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
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let Some(query) = single_valued(pairs) else {
        return error_page("A parameter appears more than once");
    };
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
        // Client asked for a scope it couldn't have. Don't redirect: the user
        // hasn't seen anything yet, and we'd be forwarding them blindly to
        // whatever the client registered (RFC 9700 §4.11.2).
        println!("Client {client_id} asked for scopes it may not have: {rscope:?}");
        return error_page("Invalid scope");
    }

    // PKCE (RFC 7636): only S256, and required from public clients (RFC 9700 §2.1.1).
    if response_type == ResponseType::Code {
        let pkce = (query.get("code_challenge"), query.get("code_challenge_method").map(String::as_str));
        let pkce_ok = match pkce {
            (Some(challenge), Some("S256")) => is_valid_challenge(challenge),
            (None, None) => client.client_secret.is_some(),
            _ => false,
        };
        if !pkce_ok {
            println!("Bad or missing PKCE from {client_id}: {pkce:?}");
            return redirect_back(&query, Some(response_type), &[("error", "invalid_request")]);
        }
    }

    let reqid = random_string(32);
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

    // Only scopes this request asked for, which /authorize checked the client
    // may have. Someone posting the form by hand can't add more.
    let scope = scopes_from_form(&form);
    if has_extra_scope(&scope, &split_scope(param(&query, "scope"))) {
        println!("Approval for scopes that weren't requested: {scope:?}");
        return error_page("Invalid scope");
    }
    let client = get_client(param(&query, "client_id")).expect("client was checked in /authorize");

    match response_type {
        Some(ResponseType::Code) => {
            let code = random_string(32);
            let response = redirect_back(&query, response_type, &[("code", &code)]);
            // save the code and request for later
            let info = CodeInfo {
                request: query,
                scope,
                user: user.preferred_username.clone(),
                grant_id: random_string(32),
                issued_at: Instant::now(),
                used: false,
            };
            state.codes.insert(code, info);
            response
        }
        Some(ResponseType::Token) => {
            // The implicit grant: the token goes straight back to the browser,
            // and never with a refresh token (RFC 6749 §4.2.2).
            let grant = Grant::new(client, scope, Some(user.preferred_username.clone()));
            let access_token = grant.issue_access_token(&app.db);
            let scope = grant.scope.join(" ");
            redirect_back(
                &query,
                response_type,
                &[("access_token", &access_token), ("token_type", "Bearer"), ("scope", &scope)],
            )
        }
        None => unreachable!("/authorize only saves requests with a known response_type"),
    }
}

/// The token endpoint. The client calls this directly (not through the
/// browser) to trade a grant, like an authorization code, for an access token.
async fn token(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let Some(body) = single_valued(pairs) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request");
    };

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

    let grant = {
        let mut state = app.inner.lock().await;
        let Some(code) = state.codes.get_mut(code_value) else {
            println!("Unknown code, {code_value}");
            return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
        };

        if code.used {
            // Someone has a copy of this code. Nothing it produced can be trusted (RFC 6749 §4.1.2).
            println!("Code {code_value} was used twice, revoking its tokens");
            revoke_grant(&app.db, &code.grant_id);
            return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }
        code.used = true;

        if code.issued_at.elapsed() > CODE_LIFETIME {
            println!("Code {code_value} has expired");
            return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }

        let code_client_id = param(&code.request, "client_id");
        if code_client_id != client.client_id {
            println!("Client mismatch, expected {code_client_id} got {}", client.client_id);
            return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }

        // The redirect URI the code was sent to must be repeated here (RFC 6749 §4.1.3).
        if code.request.get("redirect_uri").is_some_and(|sent_to| body.get("redirect_uri") != Some(sent_to)) {
            println!("Redirect URI mismatch for code {code_value}");
            return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }

        // PKCE: the verifier must hash to the challenge the code was issued for.
        let pkce_ok = match (code.request.get("code_challenge"), body.get("code_verifier")) {
            (Some(challenge), Some(verifier)) => is_valid_verifier(verifier) && pkce_challenge(verifier) == *challenge,
            (None, None) => true,
            // A verifier for a code issued without a challenge means someone
            // stripped the challenge out on the way (RFC 9700 §4.8.2).
            _ => false,
        };
        if !pkce_ok {
            println!("PKCE verification failed for code {code_value}");
            return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
        }

        Grant { id: code.grant_id.clone(), client, scope: code.scope.clone(), user: Some(code.user.clone()) }
    };

    let access_token = grant.issue_access_token(&app.db);
    let refresh_token = grant.issue_refresh_token(&app.db);
    println!("Issued tokens for code {code_value}");
    token_response(&access_token, Some(&refresh_token), &grant.scope)
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
/// `POST /introspect` (RFC 7662): tells a protected resource whether a token
/// is active, and what it's good for.
async fn introspect(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(body): Form<HashMap<String, String>>,
) -> Response {
    let resource = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(decode_client_credentials)
        .and_then(|(id, secret)| {
            PROTECTED_RESOURCES.iter().find(|r| r.resource_id == id && r.resource_secret == secret)
        });
    let Some(resource) = resource else {
        println!("Introspection by someone who isn't a protected resource");
        return (
            StatusCode::UNAUTHORIZED,
            [(WWW_AUTHENTICATE, r#"Basic realm="introspection""#)],
            Json(json!({ "error": "invalid_client" })),
        )
            .into_response();
    };

    let token = param(&body, "token");
    let active = verify_access_token(token)
        .filter(|claims| claims.get("aud").and_then(Value::as_str) == Some(resource.audience))
        // revoked tokens' records are gone
        .filter(|claims| claims.get("jti").is_some_and(|jti| app.db.find_one(|doc| doc["jti"] == *jti).is_some()));

    let Some(mut answer) = active else {
        println!("Introspection by {}: inactive token", resource.resource_id);
        return Json(json!({ "active": false })).into_response();
    };
    println!("Introspection by {}: active token", resource.resource_id);
    answer.insert("active".into(), json!(true));
    answer.insert("token_type".into(), json!("Bearer"));
    Json(answer).into_response()
}

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

    // The new access token joins the refresh token's grant.
    let grant = Grant {
        id: token["grant_id"].as_str().unwrap_or_default().to_string(),
        client,
        scope: serde_json::from_value(token["scope"].clone()).unwrap_or_default(),
        user: token["user"].as_str().map(String::from),
    };
    let access_token = grant.issue_access_token(&app.db);
    println!("for refresh token {refresh_token}");
    token_response(&access_token, Some(refresh_token), &grant.scope)
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
    let grant = Grant::new(client, scope, None);
    let access_token = grant.issue_access_token(&app.db);
    token_response(&access_token, None, &grant.scope)
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

    let grant = Grant::new(client, scope, Some(user.preferred_username.clone()));
    let access_token = grant.issue_access_token(&app.db);
    let refresh_token = client.allows_grant("refresh_token").then(|| grant.issue_refresh_token(&app.db));
    token_response(&access_token, refresh_token.as_deref(), &grant.scope)
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
    // Neither may an introspection answer.
    let token_endpoint = Router::new()
        .route("/token", post(token))
        .route("/introspect", post(introspect))
        .layer(set_header(CACHE_CONTROL, "no-store"))
        .layer(set_header(PRAGMA, "no-cache"));

    let app = Router::new()
        .route("/", get(index))
        .route("/jwks", get(|| async { ([(CONTENT_TYPE, "application/jwk-set+json")], JWKS) }))
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
