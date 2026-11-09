//! Helpers shared by every exercise.
//!
//! The original Node.js code pulls in a handful of npm packages. Each function
//! here stands in for one of them, so the exercise files can stay focused on
//! OAuth itself:
//!
//! | Node.js                         | Rust (this crate)                       |
//! |---------------------------------|-----------------------------------------|
//! | `randomstring.generate(n)`      | [`random_string`]                       |
//! | `buildUrl(base, options, hash)` | [`build_url`] / [`build_url_with_fragment`] |
//! | `encodeClientCredentials(...)`  | [`encode_client_credentials`]           |
//! | decoding `Authorization: Basic` | [`decode_client_credentials`]           |
//! | `app.set('views', ...)`         | [`set_views_dir`]                       |
//! | `res.render('index', {...})`    | [`render`]`("index", context!{...})`    |
//! | `require('nosql')`              | [`Db`]                                  |
//! | `qs.parse(body)`                | [`parse_form`]                          |
//! | `req.query.x` / `req.body.x`    | [`param`]`(&query, "x")`                |
//! | `app.listen(port, ...)`         | [`serve`]                               |
//! | PKCE's S256 (chapter 10)        | [`pkce_challenge`]                      |
//! | DPoP proofs (chapter 15)        | [`dpop::check_request`]                 |

pub mod dpop;

use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, OnceLock},
};

use axum::{
    Router,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use rand::{Rng, distr::Alphanumeric};
use serde_json::Value;
use sha2::{Digest, Sha256};

// Re-exported so exercises can write `context! { key => value }` without
// adding minijinja to their own Cargo.toml.
pub use minijinja::context;

// ---------------------------------------------------------------------------
// Random strings
// ---------------------------------------------------------------------------

/// A random alphanumeric string of `len` characters.
/// `randomstring.generate()` in Node defaults to 32 characters.
pub fn random_string(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

/// Adds query parameters to `base` (replacing any with the same name).
///
/// `build_url("http://x/authorize", &[("response_type", "code")])`
/// gives `http://x/authorize?response_type=code`.
pub fn build_url(base: &str, params: &[(&str, &str)]) -> String {
    build(base, params, None)
}

/// Same as [`build_url`], but also sets the `#fragment` part of the URL.
/// The implicit grant (chapter 6) returns tokens in the fragment.
pub fn build_url_with_fragment(base: &str, params: &[(&str, &str)], fragment: &str) -> String {
    build(base, params, Some(fragment))
}

fn build(base: &str, params: &[(&str, &str)], fragment: Option<&str>) -> String {
    let mut url = url::Url::parse(base).unwrap_or_else(|e| panic!("invalid URL {base:?}: {e}"));

    // Keep the existing query params that we are not overriding.
    let kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| !params.iter().any(|(p, _)| p == k))
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    {
        let mut query = url.query_pairs_mut();
        query.clear();
        for (k, v) in &kept {
            query.append_pair(k, v);
        }
        for (k, v) in params {
            query.append_pair(k, v);
        }
    }
    if url.query() == Some("") {
        url.set_query(None);
    }
    if fragment.is_some() {
        url.set_fragment(fragment);
    }
    url.to_string()
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

/// The PKCE code challenge for a code verifier, with the S256 method:
/// BASE64URL(SHA256(verifier)), no padding (RFC 7636 §4.2).
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

// ---------------------------------------------------------------------------
// HTTP Basic client authentication
// ---------------------------------------------------------------------------

/// Builds the value that goes after `Basic ` in an `Authorization` header:
/// base64(urlencode(client_id) + ":" + urlencode(client_secret)).
pub fn encode_client_credentials(client_id: &str, client_secret: &str) -> String {
    let raw = format!(
        "{}:{}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret)
    );
    BASE64.encode(raw)
}

/// Reverses [`encode_client_credentials`]. Takes the full header value
/// (`"Basic abc123=="`) and returns `(client_id, client_secret)`.
/// Returns `None` if the header is not a well-formed Basic header.
pub fn decode_client_credentials(auth_header: &str) -> Option<(String, String)> {
    let (scheme, encoded) = auth_header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = String::from_utf8(BASE64.decode(encoded.trim()).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((
        urlencoding::decode(id).ok()?.into_owned(),
        urlencoding::decode(secret).ok()?.into_owned(),
    ))
}

// ---------------------------------------------------------------------------
// Query strings and form bodies
// ---------------------------------------------------------------------------

/// Reads one parameter from a query string or form body, giving `""` if it
/// is missing. Works like `req.query.client_id` in the JS, where a missing
/// value is `undefined`.
///
/// Use `map.get("x")` instead when you need to tell "missing" apart from
/// "empty".
pub fn param<'a>(map: &'a HashMap<String, String>, key: &str) -> &'a str {
    map.get(key).map_or("", String::as_str)
}

/// Parses an `application/x-www-form-urlencoded` body (`a=1&b=2`) into a map.
/// An empty or non-form body just gives an empty map.
pub fn parse_form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

// ---------------------------------------------------------------------------
// HTML templates (the Node code used underscore templates via `consolidate`)
// ---------------------------------------------------------------------------

static VIEWS: OnceLock<minijinja::Environment<'static>> = OnceLock::new();

/// Sets the folder that [`render`] loads templates from. Call once in `main`.
/// Equivalent to `app.set('views', 'files/client')`.
pub fn set_views_dir(dir: impl AsRef<Path>) {
    let mut env = minijinja::Environment::new();
    env.set_loader(minijinja::path_loader(dir.as_ref()));
    if VIEWS.set(env).is_err() {
        panic!("set_views_dir() was called twice");
    }
}

/// Renders `files/<views dir>/<name>.html` with the given values.
/// Equivalent to `res.render('index', {access_token: ...})`.
///
/// ```ignore
/// render("index", context! { access_token => token, scope => scope })
/// ```
pub fn render(name: &str, ctx: minijinja::Value) -> Response {
    let env = VIEWS
        .get()
        .expect("call set_views_dir() in main before render()");
    let result = env
        .get_template(&format!("{name}.html"))
        .and_then(|template| template.render(ctx));
    match result {
        Ok(html) => Html(html).into_response(),
        Err(err) => {
            eprintln!("Template error in {name}.html: {err:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Template error in {name}.html: {err:#}"),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// A tiny file-backed "database" (the Node code used the `nosql` package)
// ---------------------------------------------------------------------------

/// Stores JSON documents, one per line, in a file.
///
/// The authorization server and the protected resource are separate programs.
/// They share tokens by opening the same file, just like the Node versions
/// share `database.nosql`.
///
/// Safe to use from many requests at once: changes inside one program take
/// turns, and a rewrite replaces the file in one step, so the other program
/// never reads a half-written file.
///
/// ```ignore
/// let db = Db::shared();
/// db.insert(json!({ "access_token": token, "client_id": id }));
/// let found = db.find_one(|doc| doc["access_token"] == token);
/// db.remove(|doc| doc["client_id"] == id);
/// ```
#[derive(Clone, Debug)]
pub struct Db {
    path: PathBuf,
}

impl Db {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Db { path: path.into() }
    }

    /// The database file shared by the authorization server and the protected
    /// resource: `database.jsonl` in the project root.
    pub fn shared() -> Self {
        Db::open(concat!(env!("CARGO_MANIFEST_DIR"), "/../database.jsonl"))
    }

    /// Deletes every document (`nosql.clear()`).
    pub fn clear(&self) {
        let _turn = writer_turn();
        self.write_all(&[]);
    }

    /// Adds a document (`nosql.insert({...})`).
    pub fn insert(&self, doc: Value) {
        let _turn = writer_turn();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap_or_else(|e| panic!("cannot open {}: {e}", self.path.display()));
        // One write call for the whole line, so lines never interleave.
        file.write_all(format!("{doc}\n").as_bytes()).expect("failed to write to database file");
    }

    /// Changes every document for which `matches` returns true and returns
    /// how many were changed.
    ///
    /// ```ignore
    /// db.update(|doc| doc["refresh_token"] == token, |doc| doc["revoked"] = json!(true));
    /// ```
    pub fn update(&self, matches: impl Fn(&Value) -> bool, mut change: impl FnMut(&mut Value)) -> usize {
        let _turn = writer_turn();
        let mut docs = self.read_all();
        let mut changed = 0;
        for doc in docs.iter_mut().filter(|doc| matches(doc)) {
            change(doc);
            changed += 1;
        }
        if changed > 0 {
            self.write_all(&docs);
        }
        changed
    }

    /// The first document for which `matches` returns true (`nosql.one()`).
    pub fn find_one(&self, matches: impl Fn(&Value) -> bool) -> Option<Value> {
        self.read_all().into_iter().find(|doc| matches(doc))
    }

    /// Every document for which `matches` returns true (`nosql.find()`).
    pub fn find_all(&self, matches: impl Fn(&Value) -> bool) -> Vec<Value> {
        self.read_all().into_iter().filter(|doc| matches(doc)).collect()
    }

    /// Deletes every document for which `matches` returns true and returns how
    /// many were deleted (`nosql.remove()`).
    pub fn remove(&self, matches: impl Fn(&Value) -> bool) -> usize {
        let _turn = writer_turn();
        let docs = self.read_all();
        let before = docs.len();
        let kept: Vec<Value> = docs.into_iter().filter(|doc| !matches(doc)).collect();
        let removed = before - kept.len();
        if removed > 0 {
            self.write_all(&kept);
        }
        removed
    }

    fn read_all(&self) -> Vec<Value> {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return Vec::new(); // file doesn't exist yet: empty database
        };
        text.lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    /// Writes a new file next to the old one, then renames it over the old
    /// one, so readers see either the old contents or the new, never half.
    fn write_all(&self, docs: &[Value]) {
        let text: String = docs.iter().map(|doc| format!("{doc}\n")).collect();
        let tmp = self.path.with_extension(format!("tmp-{}", random_string(8)));
        fs::write(&tmp, text).unwrap_or_else(|e| panic!("cannot write {}: {e}", tmp.display()));
        fs::rename(&tmp, &self.path)
            .unwrap_or_else(|e| panic!("cannot replace {}: {e}", self.path.display()));
    }
}

/// Changes to the database file take turns within this program.
fn writer_turn() -> MutexGuard<'static, ()> {
    static WRITER: Mutex<()> = Mutex::new(());
    WRITER.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// Starting a server
// ---------------------------------------------------------------------------

/// Starts serving `app` on `http://localhost:<port>` and runs until Ctrl-C.
/// Equivalent to `app.listen(port, 'localhost', ...)`.
pub async fn serve(app: Router, port: u16, name: &str) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap_or_else(|e| panic!("cannot listen on port {port} (is something else using it?): {e}"));
    println!("{name} is listening at http://localhost:{port}");
    axum::serve(listener, app).await.expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_urls() {
        assert_eq!(
            build_url("http://localhost:9001/authorize", &[("a", "1"), ("b", "x y")]),
            "http://localhost:9001/authorize?a=1&b=x+y"
        );
        assert_eq!(
            build_url("http://localhost:9000/callback?a=1&b=2", &[("b", "3")]),
            "http://localhost:9000/callback?a=1&b=3"
        );
        assert_eq!(
            build_url_with_fragment("http://localhost:9000/cb", &[], "access_token=abc"),
            "http://localhost:9000/cb#access_token=abc"
        );
    }

    #[test]
    fn pkce_matches_the_rfc_example() {
        // RFC 7636, Appendix B
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn client_credentials_round_trip() {
        let header = format!("Basic {}", encode_client_credentials("id:1", "s e/cret"));
        assert_eq!(
            decode_client_credentials(&header),
            Some(("id:1".to_string(), "s e/cret".to_string()))
        );
        assert_eq!(decode_client_credentials("Bearer abc"), None);
    }

    #[test]
    fn db_insert_find_remove() {
        let path = std::env::temp_dir().join(format!("oauth-common-test-{}.jsonl", random_string(8)));
        let db = Db::open(&path);
        db.clear();
        db.insert(serde_json::json!({ "access_token": "a", "client_id": "c1" }));
        db.insert(serde_json::json!({ "access_token": "b", "client_id": "c2" }));
        assert_eq!(db.find_one(|d| d["access_token"] == "b").unwrap()["client_id"], "c2");
        assert_eq!(db.remove(|d| d["client_id"] == "c1"), 1);
        assert!(db.find_one(|d| d["access_token"] == "a").is_none());
        assert_eq!(db.find_all(|_| true).len(), 1);
        assert_eq!(db.update(|d| d["client_id"] == "c2", |d| d["revoked"] = true.into()), 1);
        assert_eq!(db.find_one(|d| d["access_token"] == "b").unwrap()["revoked"], true);
        let _ = fs::remove_file(path);
    }
}
