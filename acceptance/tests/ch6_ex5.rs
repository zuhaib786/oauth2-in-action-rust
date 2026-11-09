//! Exercise 6-5: a native app with a loopback redirect. Spec: `exercises/ch6-ex5.md`.

use acceptance::*;

const NATIVE_ID: &str = "oauth-native-client";

// PKCE (chapter 10) is required for public clients from 10-1 on. Before
// that, the server just ignores these. The pair is RFC 7636's own example.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn native_request(redirect_uri: &str) -> [(&'static str, &str); 7] {
    [
        ("response_type", "code"),
        ("client_id", NATIVE_ID),
        ("redirect_uri", redirect_uri),
        ("scope", "foo bar"),
        ("state", "st-native"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]
}

#[test]
fn r1_r2_any_port_on_the_loopback_address() {
    for redirect_uri in ["http://127.0.0.1:53123/callback", "http://127.0.0.1:8/callback", "http://127.0.0.1/callback"] {
        let reqid = approval_page(&native_request(redirect_uri));
        let location = approve(&reqid, "alice", &["foo"]).location().to_string();
        assert_eq!(without_query(&location), redirect_uri, "sent back to the wrong place");
        assert!(query_params(&location).contains_key("code"));
    }
}

#[test]
fn r2_only_the_port_may_differ() {
    for redirect_uri in [
        "http://127.0.0.1:53123/elsewhere",
        "http://127.0.0.2:53123/callback",
        "https://127.0.0.1:53123/callback",
        "http://127.0.0.1:53123/callback?extra=1",
        "http://127.0.0.1:53123/callback/",
        "http://evil.example:53123/callback",
    ] {
        let reply = authorize(&native_request(redirect_uri));
        assert!(!reply.is_redirect(), "{redirect_uri} must be refused, but it redirected to {}", reply.location());
        reply.assert_status(400);
    }
}

#[test]
fn r3_localhost_is_not_the_loopback_address() {
    let reply = authorize(&native_request("http://localhost:53123/callback"));
    assert!(!reply.is_redirect());
    reply.assert_status(400);
}

#[test]
fn r2_other_clients_still_need_an_exact_match() {
    let reply = authorize(&[
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", "http://localhost:9999/callback"),
    ]);
    assert!(!reply.is_redirect());
}

#[test]
fn r4_the_native_client_trades_its_code_without_a_secret() {
    let redirect_uri = "http://127.0.0.1:53124/callback";
    let reqid = approval_page(&native_request(redirect_uri));
    let code = query_params(approve(&reqid, "alice", &["foo", "bar"]).location())["code"].clone();

    let reply = token_request_form(&[
        ("client_id", NATIVE_ID),
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", VERIFIER),
    ]);
    reply.assert_status(200);
    get_resource(reply.json()["access_token"].as_str().unwrap()).assert_status(200);
}

/// Starts native-client and returns it with the authorization URL it printed.
fn start_native_client() -> (Running, String) {
    let mut app = Running::start(&build_bin("native-client"), &[]);
    let url = app.wait_for_line("the authorization URL", |line| line.trim().starts_with(&format!("{AS_URL}/authorize?")));
    (app, url.trim().to_string())
}

#[test]
fn r6_r7_r9_r10_r11_native_client_logs_in_and_calls_the_resource() {
    let (app, url) = start_native_client();

    let asked = query_params(&url);
    assert_eq!(asked.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(asked.get("client_id").map(String::as_str), Some(NATIVE_ID));
    assert_eq!(scope_set(asked.get("scope").map_or("", String::as_str)), scope_set("foo bar"));
    assert!(asked.get("state").is_some_and(|s| s.len() >= 16), "state should be long and random: {url}");
    let redirect_uri = asked["redirect_uri"].clone();
    assert!(redirect_uri.starts_with("http://127.0.0.1:") && redirect_uri.ends_with("/callback"), "redirect_uri was {redirect_uri}");

    // the browser asks for a favicon first; the app must keep waiting
    let base = redirect_uri.trim_end_matches("/callback");
    http().get(format!("{base}/favicon.ico")).call().assert_status(404);

    // the user approves in the browser, which then goes back to the app
    let page = http().get(&url).call();
    let back = approve(&reqid(&page.body), "alice", &["foo", "bar"]);
    let landing = http().get(back.location()).call();
    landing.assert_status(200);
    assert!(landing.header("content-type").unwrap_or("").starts_with("text/html"), "answer the browser with a page");

    let (status, stdout) = app.wait_for_exit();
    assert!(status.success(), "native-client failed ({status}). stdout:\n{stdout}");
    assert!(stdout.contains("Protected Resource"), "print the resource's JSON. stdout:\n{stdout}");
}

#[test]
fn r8_a_forged_callback_is_refused() {
    let (app, url) = start_native_client();
    let redirect_uri = query_params(&url)["redirect_uri"].clone();

    let forged = http().get(&redirect_uri).query(&[("code", "attackers-code"), ("state", "forged")]).call();
    assert!(forged.status.is_success() || forged.status.is_client_error(), "answer the browser, got {}", forged.status);

    let (status, stdout) = app.wait_for_exit();
    assert!(!status.success(), "a wrong state must make native-client fail. stdout:\n{stdout}");
    assert!(!stdout.contains("Protected Resource"));
}

#[test]
fn r8_an_error_from_the_authorization_server_is_reported() {
    let (app, url) = start_native_client();

    let page = http().get(&url).call();
    let back = deny(&reqid(&page.body));
    assert!(query_params(back.location()).contains_key("error"));
    http().get(back.location()).call();

    let (status, _) = app.wait_for_exit();
    assert!(!status.success(), "access_denied must make native-client fail");
}
