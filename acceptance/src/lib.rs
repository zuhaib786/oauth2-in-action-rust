//! Helpers for the acceptance tests in `tests/`.
//!
//! The tests talk to the three running servers over HTTP, the way a browser
//! or curl would. They don't care how your code is written inside, only what
//! it answers. Start the servers first, then:
//!
//! ```text
//! cargo test -p acceptance --test ch6_ex1    # one exercise
//! cargo test -p acceptance                   # everything so far
//! ```
//!
//! Every helper panics with a readable message when something is off, so a
//! failing test tells you what it expected.

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, MutexGuard, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use reqwest::{
    StatusCode,
    blocking::{Client, RequestBuilder},
    header::HeaderMap,
    redirect::Policy,
};
use serde_json::Value;

pub use reqwest::blocking::Client as HttpClient;
pub use serde_json::json;

pub const CLIENT_URL: &str = "http://localhost:9000";
pub const AS_URL: &str = "http://localhost:9001";
pub const RS_URL: &str = "http://localhost:9002";

/// The web client from chapter 3.
pub const CLIENT_ID: &str = "oauth-client-1";
pub const CLIENT_SECRET: &str = "oauth-client-secret-1";
pub const REDIRECT_URI: &str = "http://localhost:9000/callback";
pub const CLIENT_SCOPE: &str = "foo bar read write delete fruit veggies meats movies foods music";

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/// An HTTP client that does not follow redirects, so tests can look at them.
pub fn http() -> Client {
    Client::builder().redirect(Policy::none()).build().expect("build HTTP client")
}

/// Like [`http`], but keeps cookies between requests, like a browser.
/// Two `browser()`s are two different people.
pub fn browser() -> Client {
    Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .expect("build HTTP client")
}

/// A response, read in full.
#[derive(Debug)]
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: String,
}

impl Reply {
    /// The value of a header, if present (and valid text).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Every value of a header that may appear several times.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        self.headers.get_all(name).iter().filter_map(|v| v.to_str().ok()).collect()
    }

    pub fn is_redirect(&self) -> bool {
        self.status.is_redirection()
    }

    /// Where a redirect points. Panics if this is not a redirect.
    pub fn location(&self) -> &str {
        assert!(
            self.is_redirect(),
            "expected a redirect, got {}\n{}",
            self.status,
            excerpt(&self.body)
        );
        self.header("location").expect("redirect without a Location header")
    }

    /// The body parsed as JSON. Panics if it isn't JSON.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| {
            panic!("expected a JSON body ({e}), got {}:\n{}", self.status, excerpt(&self.body))
        })
    }

    /// Panics unless the status is `expected`, showing the body if not.
    #[track_caller]
    pub fn assert_status(&self, expected: u16) -> &Self {
        assert_eq!(
            self.status.as_u16(),
            expected,
            "unexpected status, body was:\n{}",
            excerpt(&self.body)
        );
        self
    }
}

fn excerpt(body: &str) -> String {
    let body = body.trim();
    if body.chars().count() > 1200 { format!("{}…", body.chars().take(1200).collect::<String>()) } else { body.to_string() }
}

/// `.call()` sends a request and reads the whole response.
pub trait Call {
    fn call(self) -> Reply;
}

impl Call for RequestBuilder {
    #[track_caller]
    fn call(self) -> Reply {
        let res = match self.send() {
            Ok(res) => res,
            Err(err) if err.is_connect() => panic!(
                "\n\nCould not connect to {}.\nStart the servers first, each in its own terminal:\n  \
                 cargo run -p authorization-server\n  cargo run -p protected-resource\n  cargo run -p client\n\n",
                err.url().map_or("a server".into(), |u| u.to_string())
            ),
            Err(err) => panic!("request failed: {err}"),
        };
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.text().unwrap_or_default();
        Reply { status, headers, body }
    }
}

// ---------------------------------------------------------------------------
// URLs
// ---------------------------------------------------------------------------

/// The query parameters of a URL.
pub fn query_params(url: &str) -> HashMap<String, String> {
    let url = url::Url::parse(url).unwrap_or_else(|e| panic!("bad URL {url:?}: {e}"));
    url.query_pairs().into_owned().collect()
}

/// The parameters in a URL's `#fragment`, which the implicit grant uses.
pub fn fragment_params(url: &str) -> HashMap<String, String> {
    let url = url::Url::parse(url).unwrap_or_else(|e| panic!("bad URL {url:?}: {e}"));
    url::form_urlencoded::parse(url.fragment().unwrap_or("").as_bytes()).into_owned().collect()
}

/// The URL without its query and fragment.
pub fn without_query(url: &str) -> String {
    let mut url = url::Url::parse(url).unwrap_or_else(|e| panic!("bad URL {url:?}: {e}"));
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

// ---------------------------------------------------------------------------
// Authorization server: the front channel (browser) part
// ---------------------------------------------------------------------------

/// `GET /authorize` with these query parameters.
pub fn authorize(params: &[(&str, &str)]) -> Reply {
    http().get(format!("{AS_URL}/authorize")).query(params).call()
}

/// Opens the approval page and returns its `reqid`. Panics if the
/// authorization server doesn't show the approval page.
#[track_caller]
pub fn approval_page(params: &[(&str, &str)]) -> String {
    let reply = authorize(params);
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "expected the approval page for {params:?}, got {}",
        if reply.is_redirect() { format!("a redirect to {}", reply.location()) } else { reply.body.clone() }
    );
    reqid(&reply.body)
}

/// Reads the hidden `reqid` field out of the approval page.
#[track_caller]
pub fn reqid(page: &str) -> String {
    hidden_field(page, "reqid").unwrap_or_else(|| panic!("no reqid on the approval page:\n{}", excerpt(page)))
}

/// The scope checkboxes on the approval page.
pub fn scopes_on_page(page: &str) -> Vec<String> {
    page.match_indices("name=\"scope_")
        .filter_map(|(at, m)| page[at + m.len()..].split('"').next())
        .map(String::from)
        .collect()
}

fn hidden_field(page: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = page.find(&marker)? + marker.len();
    Some(page[start..].split('"').next()?.to_string())
}

/// Clicks Approve on the approval page as `user`, with these scope boxes ticked.
pub fn approve(reqid: &str, user: &str, scopes: &[&str]) -> Reply {
    let mut form = vec![
        ("reqid".to_string(), reqid.to_string()),
        ("user".to_string(), user.to_string()),
        ("approve".to_string(), "Approve".to_string()),
    ];
    form.extend(scopes.iter().map(|s| (format!("scope_{s}"), "on".to_string())));
    http().post(format!("{AS_URL}/approve")).form(&form).call()
}

/// Clicks Deny on the approval page.
pub fn deny(reqid: &str) -> Reply {
    http()
        .post(format!("{AS_URL}/approve"))
        .form(&[("reqid", reqid), ("deny", "Deny")])
        .call()
}

/// Runs the browser part of the code flow for oauth-client-1 and returns
/// the authorization code. `user` approves every scope in `scope`.
#[track_caller]
pub fn get_code(scope: &str, user: &str) -> String {
    get_code_with(&[], scope, user)
}

/// Like [`get_code`], with extra `/authorize` parameters (e.g. PKCE).
#[track_caller]
pub fn get_code_with(extra: &[(&str, &str)], scope: &str, user: &str) -> String {
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", scope),
        ("state", "test-state"),
    ];
    params.extend_from_slice(extra);
    let reqid = approval_page(&params);
    let scopes: Vec<&str> = scope.split_whitespace().collect();
    let reply = approve(&reqid, user, &scopes);
    let to = query_params(reply.location());
    to.get("code")
        .unwrap_or_else(|| panic!("no code in the redirect {}", reply.location()))
        .clone()
}

// ---------------------------------------------------------------------------
// Authorization server: the back channel (token endpoint)
// ---------------------------------------------------------------------------

/// `POST /token` authenticated as oauth-client-1 with HTTP Basic.
pub fn token_request(form: &[(&str, &str)]) -> Reply {
    token_request_as(CLIENT_ID, CLIENT_SECRET, form)
}

/// `POST /token` authenticated with HTTP Basic as any client.
pub fn token_request_as(client_id: &str, client_secret: &str, form: &[(&str, &str)]) -> Reply {
    http()
        .post(format!("{AS_URL}/token"))
        .basic_auth(enc(client_id), Some(enc(client_secret)))
        .form(form)
        .call()
}

/// `POST /token` with no Authorization header: whatever is in `form` is all
/// the server gets (public clients send just their `client_id`).
pub fn token_request_form(form: &[(&str, &str)]) -> Reply {
    http().post(format!("{AS_URL}/token")).form(form).call()
}

/// RFC 6749 §2.3.1: the client id and secret are form-urlencoded before
/// they go into the Basic header.
fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// A token response for oauth-client-1, from a fresh code approved by `user`.
#[track_caller]
pub fn tokens(scope: &str, user: &str) -> Value {
    let code = get_code(scope, user);
    let reply = token_request(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT_URI),
    ]);
    reply.assert_status(200);
    reply.json()
}

/// Just the access token from [`tokens`].
#[track_caller]
pub fn access_token(scope: &str, user: &str) -> String {
    tokens(scope, user)["access_token"].as_str().expect("access_token in token response").to_string()
}

/// A space-separated scope string as a set, so order doesn't matter:
/// `scope_set(&token["scope"]) == scope_set("read write")`.
pub fn scope_set(scope: impl AsScope) -> std::collections::BTreeSet<String> {
    scope.as_scope().split_whitespace().map(String::from).collect()
}

pub trait AsScope {
    fn as_scope(&self) -> &str;
}
impl AsScope for &str {
    fn as_scope(&self) -> &str {
        self
    }
}
impl AsScope for &Value {
    fn as_scope(&self) -> &str {
        self.as_str().unwrap_or_else(|| panic!("scope should be a space-separated string, got {self}"))
    }
}

/// The `error` code of a JSON error response.
pub fn error_code(reply: &Reply) -> String {
    reply.json()["error"].as_str().unwrap_or("").to_string()
}

// ---------------------------------------------------------------------------
// Protected resource
// ---------------------------------------------------------------------------

/// `POST /resource` with `Authorization: Bearer <token>`.
pub fn get_resource(token: &str) -> Reply {
    http().post(format!("{RS_URL}/resource")).bearer_auth(token).call()
}

// ---------------------------------------------------------------------------
// The client app (port 9000)
// ---------------------------------------------------------------------------

static CLIENT_APP: Mutex<()> = Mutex::new(());

/// The client app keeps state between requests, so tests that drive it take
/// turns. Hold the guard for the whole test.
pub fn client_app_lock() -> MutexGuard<'static, ()> {
    CLIENT_APP.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Logs in through the client app the way a person would: client `/authorize`
/// → approval page → Approve → client `/callback`. Ticks every scope offered
/// unless `scopes` says otherwise. Returns the client's answer to `/callback`.
#[track_caller]
pub fn client_login(browser: &Client, user: &str, scopes: Option<&[&str]>) -> Reply {
    let start = browser.get(format!("{CLIENT_URL}/authorize")).call();
    let to_as = start.location().to_string();
    let page = browser.get(&to_as).call();
    assert_eq!(page.status, StatusCode::OK, "expected the approval page at {to_as}:\n{}", page.body);
    let offered = scopes_on_page(&page.body);
    let ticked: Vec<&str> = match scopes {
        Some(s) => s.to_vec(),
        None => offered.iter().map(String::as_str).collect(),
    };
    let back = approve(&reqid(&page.body), user, &ticked);
    browser.get(back.location()).call()
}

/// The access token the client app's home page shows, or `None` for "NONE".
pub fn client_shown_token(browser: &Client) -> Option<String> {
    let page = browser.get(format!("{CLIENT_URL}/")).call().body;
    let marker = "Access token value: <span class=\"label label-danger\">";
    let start = page.find(marker)? + marker.len();
    let token = page[start..].split('<').next()?.trim();
    (token != "NONE" && !token.is_empty()).then(|| token.to_string())
}

// ---------------------------------------------------------------------------
// Programs you write (chapter 6 on)
// ---------------------------------------------------------------------------

/// Builds a binary from this workspace with `cargo build` and returns the
/// path to the executable. Panics with the compiler's output if it doesn't
/// build, or with a hint if the package doesn't exist yet.
#[track_caller]
pub fn build_bin(package: &str) -> PathBuf {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let output = Command::new(cargo)
        .args(["build", "-q", "-p", package, "--bin", package, "--message-format=json"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
        .output()
        .expect("run cargo build");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("did not match any packages") {
        panic!("\n\nThere is no `{package}` crate yet. Create it and add it to the workspace members in Cargo.toml.\n\n");
    }
    if !output.status.success() {
        let errors: Vec<String> = stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter_map(|msg| msg["message"]["rendered"].as_str().map(String::from))
            .collect();
        panic!("\n\n`{package}` doesn't build:\n{}{stderr}", errors.join(""));
    }
    stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|msg| msg["reason"] == "compiler-artifact" && msg["target"]["name"] == package)
        .find_map(|msg| msg["executable"].as_str().map(PathBuf::from))
        .unwrap_or_else(|| panic!("cargo built no `{package}` executable"))
}

/// A word nobody else will use, to find in shared data later.
pub fn unique(prefix: &str) -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    format!("{prefix}{nanos}")
}

/// A program running in the background, whose stdout the test reads line by
/// line while it runs.
pub struct Running {
    child: Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
    stderr: Arc<Mutex<String>>,
}

impl Running {
    /// Starts `program` with `NO_BROWSER=1` set, so it doesn't open a browser.
    pub fn start(program: &Path, args: &[&str]) -> Running {
        let mut child = Command::new(program)
            .args(args)
            .env("NO_BROWSER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("cannot start {}: {e}", program.display()));

        let (send, lines) = mpsc::channel();
        let stdout = child.stdout.take().expect("piped stdout");
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });

        let stderr = Arc::new(Mutex::new(String::new()));
        let mut pipe = child.stderr.take().expect("piped stderr");
        let sink = Arc::clone(&stderr);
        thread::spawn(move || {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            sink.lock().unwrap_or_else(|p| p.into_inner()).push_str(&text);
        });

        Running { child, lines, seen: Vec::new(), stderr }
    }

    /// Waits for a line of stdout that `wanted` accepts and returns it.
    #[track_caller]
    pub fn wait_for_line(&mut self, what: &str, wanted: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if wanted(&line) {
                        return line;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = self.child.kill();
        panic!("the program never printed {what}.\nstdout so far:\n{}\nstderr:\n{}", self.seen.join("\n"), self.stderr());
    }

    /// Waits for the program to exit and returns its exit status and all of
    /// its stdout.
    #[track_caller]
    pub fn wait_for_exit(mut self) -> (ExitStatus, String) {
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("check on the program") {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("the program didn't exit within 20 s.\nstdout:\n{}", self.seen.join("\n"));
            }
            thread::sleep(Duration::from_millis(50));
        };
        // the reader thread ends when the pipe closes
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(2)) {
            self.seen.push(line);
        }
        (status, self.seen.join("\n"))
    }

    /// Everything the program wrote to stderr so far (all of it once it has exited).
    pub fn stderr(&self) -> String {
        thread::sleep(Duration::from_millis(100));
        self.stderr.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
