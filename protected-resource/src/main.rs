//! The OAuth protected resource (http://localhost:9002).
//!
//! APIs that only answer requests carrying a valid access token issued by
//! the authorization server.
//!
//! Run it with:  cargo run -p protected-resource

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{FromRequest, Query, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, STRICT_TRANSPORT_SECURITY, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use oauth_common::{context, param, parse_form, render};
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    set_header::SetResponseHeaderLayer,
};

/// Named in every `WWW-Authenticate` challenge.
const REALM: &str = "localhost:9002";

/// The only issuer whose tokens we take.
const ISSUER: &str = "http://localhost:9001/";
/// Who we are, as tokens name us in `aud`.
const AUDIENCE: &str = "http://localhost:9002/";
/// How far apart our clock and the authorization server's may be.
const CLOCK_SKEW: u64 = 30;
/// Where the authorization server publishes the keys it signs tokens with.
const JWKS_URI: &str = "http://localhost:9001/jwks";
/// Don't fetch the JWK Set more often than this, however many unknown `kid`s
/// show up.
const JWKS_REFETCH_INTERVAL: Duration = Duration::from_secs(10);

/// The only origin whose pages may call these APIs from a browser.
const CLIENT_ORIGIN: &str = "http://localhost:9000";

/// CORS for the client app's origin and nobody else. `list` (unlike `exact`)
/// leaves the header out entirely when the origin doesn't match.
fn cors() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::list([HeaderValue::from_static(CLIENT_ORIGIN)]))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        // so a script can see why it was refused
        .expose_headers([WWW_AUTHENTICATE])
        .max_age(Duration::from_secs(600))
}

#[derive(Clone)]
struct AppState {
    /// The Words API's data (`var savedWords = []` in the JS).
    saved_words: Arc<Mutex<Vec<String>>>,
    /// The authorization server's public keys.
    keys: Arc<Mutex<Keys>>,
    http: reqwest::Client,
}

/// The authorization server's JWK Set, as last fetched.
#[derive(Default)]
struct Keys {
    set: Option<JwkSet>,
    fetched_at: Option<Instant>,
}

impl AppState {
    /// The authorization server's key with this `kid`. Fetches the JWK Set
    /// when the key isn't known yet: the server may have rotated keys.
    async fn signing_key(&self, kid: &str) -> Option<DecodingKey> {
        let mut keys = self.keys.lock().await;
        let known = |keys: &Keys| keys.set.as_ref().and_then(|set| set.find(kid)).cloned();
        if known(&keys).is_none() && keys.fetched_at.is_none_or(|at| at.elapsed() >= JWKS_REFETCH_INTERVAL) {
            keys.fetched_at = Some(Instant::now());
            match self.fetch_jwks().await {
                Ok(set) => keys.set = Some(set),
                Err(e) => println!("Couldn't fetch {JWKS_URI}: {e}"),
            }
        }
        DecodingKey::from_jwk(&known(&keys)?).ok()
    }

    async fn fetch_jwks(&self) -> reqwest::Result<JwkSet> {
        println!("Fetching {JWKS_URI}");
        self.http.get(JWKS_URI).send().await?.error_for_status()?.json().await
    }
}

// ---------------------------------------------------------------------------
// Finding and checking the access token
// ---------------------------------------------------------------------------

/// Why a request was turned away. Each kind answers with its own status and
/// `WWW-Authenticate` challenge (RFC 6750 §3), so the client can tell them apart.
#[derive(Debug)]
enum Refusal {
    /// No token at all. The challenge carries no error code (RFC 6750 §3.1).
    NoToken,
    /// A token we don't recognise.
    InvalidToken,
    /// A malformed request, like a token sent two ways at once.
    InvalidRequest,
    /// A good token without the scope this needs.
    InsufficientScope(&'static str),
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let (status, error, scope) = match self {
            Refusal::NoToken => (StatusCode::UNAUTHORIZED, None, None),
            Refusal::InvalidToken => (StatusCode::UNAUTHORIZED, Some("invalid_token"), None),
            Refusal::InvalidRequest => (StatusCode::BAD_REQUEST, Some("invalid_request"), None),
            Refusal::InsufficientScope(scope) => (StatusCode::FORBIDDEN, Some("insufficient_scope"), Some(scope)),
        };
        let mut challenge = format!(r#"Bearer realm="{REALM}""#);
        if let Some(error) = error {
            challenge.push_str(&format!(r#", error="{error}""#));
        }
        if let Some(scope) = scope {
            challenge.push_str(&format!(r#", scope="{scope}""#));
        }
        (status, [(WWW_AUTHENTICATE, challenge)]).into_response()
    }
}

/// Finds the access token in the `Authorization: Bearer` header or the form
/// body (never the URL: RFC 6750 §2.3), then checks it. Returns its claims.
async fn get_access_token(app: &AppState, headers: &HeaderMap, form: &HashMap<String, String>) -> Result<Value, Refusal> {
    let from_header = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim().to_string());

    let in_token = match (from_header, form.get("access_token")) {
        // "Clients MUST NOT use more than one method" (RFC 6750 §2)
        (Some(_), Some(_)) => return Err(Refusal::InvalidRequest),
        (Some(token), None) => token,
        (None, Some(token)) => token.clone(),
        (None, None) => return Err(Refusal::NoToken),
    };

    let claims = check_jwt(app, &in_token).await;
    match &claims {
        Some(claims) => println!("Accepted a token for {}", claims["sub"]),
        None => println!("Refused token {in_token}"),
    }
    claims.map(Value::Object).ok_or(Refusal::InvalidToken)
}

/// Checks a signed JWT access token (RFC 9068 §4) and returns its claims.
async fn check_jwt(app: &AppState, token: &str) -> Option<Map<String, Value>> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    let typ = header.typ?.to_ascii_lowercase();
    if typ != "at+jwt" && typ != "application/at+jwt" {
        return None;
    }
    // RS256 and nothing else, whatever the header asks for (RFC 8725 §3.1)
    if header.alg != Algorithm::RS256 {
        return None;
    }
    let key = app.signing_key(&header.kid?).await?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_nbf = true;
    validation.leeway = CLOCK_SKEW;

    match jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation) {
        Ok(token) => Some(token.claims),
        Err(e) => {
            println!("Bad token: {e}");
            None
        }
    }
}

/// Is this body a form we may look for a token in? (RFC 6750 §2.2)
fn has_form_body(method: &Method, headers: &HeaderMap) -> bool {
    let is_form = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|content_type| content_type.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"));
    is_form && method != Method::GET
}

/// A valid access token that came with the request.
///
/// Putting `token: AccessToken` in a handler's arguments means "this endpoint
/// needs a valid token". Without one, axum answers 401 Unauthorized and never
/// calls the handler. This replaces the book's `getAccessToken` and
/// `requireAccessToken` Express middleware.
struct AccessToken {
    /// The token's claims: `sub`, `client_id`, `scope`, ...
    claims: Value,
    /// The request's form body. We had to read the body to look for a token
    /// in it, so handlers that need other form fields get them from here.
    form: HashMap<String, String>,
}

impl AccessToken {
    /// True if the token was issued with this scope. The `scope` claim is
    /// space-separated, like `"read write"`.
    fn has_scope(&self, scope: &str) -> bool {
        self.claims["scope"]
            .as_str()
            .is_some_and(|scopes| scopes.split(' ').any(|s| s == scope))
    }
}

/// This is the code that runs when a handler asks for an `AccessToken`.
impl FromRequest<AppState> for AccessToken {
    type Rejection = Refusal;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let form = if has_form_body(&parts.method, &parts.headers) {
            let body = axum::body::to_bytes(body, 64 * 1024).await.map_err(|_| Refusal::InvalidRequest)?;
            parse_form(&String::from_utf8_lossy(&body))
        } else {
            HashMap::new()
        };

        let claims = get_access_token(state, &parts.headers, &form).await?;
        Ok(AccessToken { claims, form })
    }
}

// ---------------------------------------------------------------------------
// APIs
// ---------------------------------------------------------------------------

async fn resource(_token: AccessToken) -> Response {
    Json(json!({
        "name": "Protected Resource",
        "description": "This data has been protected by OAuth 2.0"
    }))
    .into_response()
}

/// Milliseconds since 1970, like JavaScript's `Date.now()`.
fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// 403 Forbidden, telling the client which scope it was missing.
fn insufficient_scope(scope: &'static str) -> Response {
    Refusal::InsufficientScope(scope).into_response()
}

async fn get_words(State(app): State<AppState>, token: AccessToken) -> Response {
    if !token.has_scope("read") {
        return insufficient_scope("read");
    }
    let saved_words = app.saved_words.lock().await;
    Json(json!({ "words": saved_words.join(" "), "timestamp": now_millis() })).into_response()
}

async fn add_word(State(app): State<AppState>, token: AccessToken) -> Response {
    if !token.has_scope("write") {
        return insufficient_scope("write");
    }
    if let Some(word) = token.form.get("word") {
        app.saved_words.lock().await.push(word.clone());
    }
    StatusCode::CREATED.into_response()
}

async fn delete_word(State(app): State<AppState>, token: AccessToken) -> Response {
    if !token.has_scope("delete") {
        return insufficient_scope("delete");
    }
    app.saved_words.lock().await.pop();
    StatusCode::NO_CONTENT.into_response()
}

async fn produce(token: AccessToken) -> Response {
    let mut produce = json!({ "fruit": [], "veggies": [], "meats": [] });
    if token.has_scope("fruit") {
        produce["fruit"] = json!(["apple", "banana", "kiwi"]);
    }
    if token.has_scope("veggies") {
        produce["veggies"] = json!(["lettuce", "onion", "potato"]);
    }
    if token.has_scope("meats") {
        produce["meats"] = json!(["bacon", "steak", "chicken breast"]);
    }
    println!("Sending produce: {produce}");
    Json(produce).into_response()
}

async fn favorites(token: AccessToken) -> Response {
    let alice_favorites = json!({
        "movies": ["The Multidmensional Vector", "Space Fights", "Jewelry Boss"],
        "foods": ["bacon", "pizza", "bacon pizza"],
        "music": ["techno", "industrial", "alternative"],
    });
    let bob_favorites = json!({
        "movies": ["An Unrequited Love", "Several Shades of Turquoise", "Think Of The Children"],
        "foods": ["bacon", "kale", "gravel"],
        "music": ["baroque", "ukulele", "baroque ukulele"],
    });

    // The token says whose it is.
    let response = match token.claims["sub"].as_str() {
        Some("9XE3-JI34-00132A") => json!({ "user": "Alice", "favorites": alice_favorites }),
        Some("1ZT5-OE63-57383B") => json!({ "user": "Bob", "favorites": bob_favorites }),
        _ => json!({ "user": "Unknown", "favorites": { "movies": [], "foods": [], "music": [] } }),
    };
    Json(response).into_response()
}

// ---------------------------------------------------------------------------
// Hello World API (chapter 8)
// ---------------------------------------------------------------------------

/// Greets you in the language you ask for: `/helloWorld?language=en`.
/// Always JSON, and never repeats what it was sent.
async fn hello_world(Query(query): Query<HashMap<String, String>>, _token: AccessToken) -> Response {
    let greeting = match param(&query, "language") {
        "en" => "Hello World",
        "de" => "Hallo Welt",
        "it" => "Ciao Mondo",
        "fr" => "Bonjour monde",
        "es" => "Hola mundo",
        _ => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_language" }))).into_response(),
    };
    Json(json!({ "greeting": greeting })).into_response()
}

#[tokio::main]
async fn main() {
    oauth_common::set_views_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/templates"));

    let state = AppState { saved_words: Arc::default(), keys: Arc::default(), http: reqwest::Client::new() };

    let app = Router::new()
        .route("/", get(|| async { render("index", context! {}) }))
        .route("/resource", post(resource))
        .route("/words", get(get_words).post(add_word).delete(delete_word))
        .route("/produce", get(produce))
        .route("/favorites", get(favorites))
        .route("/helloWorld", get(hello_world))
        .layer(cors())
        // Browsers must not guess that a JSON answer is really HTML.
        .layer(SetResponseHeaderLayer::overriding(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        // Once seen over HTTPS: never talk to this host over plain HTTP again.
        .layer(SetResponseHeaderLayer::overriding(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        ))
        .with_state(state);

    oauth_common::serve(app, 9002, "OAuth Resource Server").await;
}
