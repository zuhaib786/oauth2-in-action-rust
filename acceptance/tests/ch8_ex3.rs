//! Exercise 8-3: security headers. Spec: `exercises/ch8-ex3.md`.

use acceptance::*;

#[test]
fn r1_the_protected_resource_asks_for_https_only() {
    for reply in [http().get(format!("{RS_URL}/")).call(), http().post(format!("{RS_URL}/resource")).call()] {
        assert_eq!(reply.header("strict-transport-security"), Some("max-age=31536000"), "on a {} response", reply.status);
    }
}

#[track_caller]
fn assert_not_cached(reply: &Reply) {
    assert_eq!(reply.header("cache-control"), Some("no-store"), "on a {} token response", reply.status);
    assert_eq!(reply.header("pragma"), Some("no-cache"), "on a {} token response", reply.status);
}

#[test]
fn r2_token_responses_are_never_cached() {
    let code = get_code("foo", "alice");
    let success = token_request(&[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT_URI)]);
    success.assert_status(200);
    assert_not_cached(&success);

    assert_not_cached(&token_request(&[("grant_type", "magic")]));
    assert_not_cached(&token_request_as(CLIENT_ID, "wrong", &[("grant_type", "authorization_code")]));
}

/// A few different authorization server responses: a page, an error page,
/// a redirect and JSON.
fn as_responses() -> Vec<(&'static str, Reply)> {
    let request = [
        ("response_type", "code"),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "foo"),
        ("state", "s"),
    ];
    let approval = authorize(&request);
    let redirect = approve(&reqid(&approval.body), "alice", &["foo"]);
    vec![
        ("the approval page", approval),
        ("an error page", authorize(&[("client_id", "nobody")])),
        ("the redirect back to the client", redirect),
        ("a token error", token_request(&[("grant_type", "magic")])),
        ("the home page", http().get(format!("{AS_URL}/")).call()),
    ]
}

#[test]
fn r3_nothing_may_frame_the_authorization_server() {
    for (what, reply) in as_responses() {
        assert_eq!(reply.header("x-frame-options").map(str::to_ascii_uppercase).as_deref(), Some("DENY"), "on {what}");
        let csp = reply.header("content-security-policy").unwrap_or("");
        assert!(csp.contains("frame-ancestors 'none'"), "on {what}, CSP was {csp:?}");
    }
}

#[test]
fn r4_r5_nosniff_and_no_referrer_everywhere() {
    for (what, reply) in as_responses() {
        assert_eq!(reply.header("x-content-type-options"), Some("nosniff"), "on {what}");
        assert_eq!(reply.header("referrer-policy"), Some("no-referrer"), "on {what}");
    }
}
