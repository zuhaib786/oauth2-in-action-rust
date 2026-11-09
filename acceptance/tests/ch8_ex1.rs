//! Exercise 8-1: protected resource answers. Spec: `exercises/ch8-ex1.md`.

use acceptance::*;

const REALM: &str = r#"realm="localhost:9002""#;

fn hello(token: &str, language: &str) -> Reply {
    http().get(format!("{RS_URL}/helloWorld")).query(&[("language", language)]).bearer_auth(token).call()
}

#[test]
fn r1_greetings_are_json() {
    let token = access_token("foo", "alice");
    for (language, greeting) in [("en", "Hello World"), ("de", "Hallo Welt"), ("es", "Hola mundo")] {
        let reply = hello(&token, language);
        reply.assert_status(200);
        assert!(reply.header("content-type").unwrap_or("").starts_with("application/json"), "for {language}");
        assert_eq!(reply.json()["greeting"], greeting);
    }
}

#[test]
fn r2_an_unknown_language_is_not_echoed_back() {
    let token = access_token("foo", "alice");
    let reply = hello(&token, "<script>alert('xss')</script>");
    reply.assert_status(400);
    assert!(reply.header("content-type").unwrap_or("").starts_with("application/json"));
    assert_eq!(reply.json()["error"], "invalid_language");
    assert!(!reply.body.contains("script"), "the input must not come back: {}", reply.body);
}

#[test]
fn r3_every_response_says_nosniff() {
    let token = access_token("foo", "alice");
    let replies = [
        ("200", hello(&token, "en")),
        ("400", hello(&token, "xx")),
        ("401", http().post(format!("{RS_URL}/resource")).call()),
        ("index", http().get(format!("{RS_URL}/")).call()),
    ];
    for (what, reply) in replies {
        assert_eq!(reply.header("x-content-type-options"), Some("nosniff"), "on the {what} response");
    }
}

#[test]
fn r4_a_token_in_the_query_string_is_ignored() {
    let token = access_token("foo", "alice");
    let reply = http().post(format!("{RS_URL}/resource")).query(&[("access_token", token.as_str())]).call();
    reply.assert_status(401);
}

#[test]
fn r5_a_form_body_must_be_a_form() {
    let token = access_token("foo", "alice");
    let reply = http()
        .post(format!("{RS_URL}/resource"))
        .header("content-type", "text/plain")
        .body(format!("access_token={token}"))
        .call();
    reply.assert_status(401);

    // the real thing still works
    let form = http().post(format!("{RS_URL}/resource")).form(&[("access_token", token.as_str())]).call();
    form.assert_status(200);
}

#[test]
fn r6_r9_two_ways_at_once_is_an_invalid_request() {
    let token = access_token("foo", "alice");
    let reply = http()
        .post(format!("{RS_URL}/resource"))
        .bearer_auth(&token)
        .form(&[("access_token", token.as_str())])
        .call();
    reply.assert_status(400);
    let challenge = reply.header("www-authenticate").unwrap_or("");
    assert!(challenge.starts_with("Bearer "), "{challenge:?}");
    assert!(challenge.contains(r#"error="invalid_request""#), "{challenge:?}");
}

#[test]
fn r7_no_token_gets_a_challenge_without_an_error_code() {
    let reply = http().post(format!("{RS_URL}/resource")).call();
    reply.assert_status(401);
    let challenge = reply.header("www-authenticate").unwrap_or("");
    assert!(challenge.starts_with("Bearer "), "{challenge:?}");
    assert!(challenge.contains(REALM), "{challenge:?}");
    assert!(!challenge.contains("error="), "no error code when no token was sent: {challenge:?}");
}

#[test]
fn r8_a_bad_token_is_an_invalid_token() {
    let reply = get_resource("not-a-real-token");
    reply.assert_status(401);
    let challenge = reply.header("www-authenticate").unwrap_or("");
    assert!(challenge.contains(REALM), "{challenge:?}");
    assert!(challenge.contains(r#"error="invalid_token""#), "{challenge:?}");
}

#[test]
fn r10_insufficient_scope_quotes_the_realm() {
    let token = access_token("read", "alice");
    let reply = http().delete(format!("{RS_URL}/words")).bearer_auth(&token).call();
    reply.assert_status(403);
    let challenge = reply.header("www-authenticate").unwrap_or("");
    assert!(challenge.contains(REALM), "{challenge:?}");
    assert!(challenge.contains(r#"error="insufficient_scope""#), "{challenge:?}");
    assert!(challenge.contains(r#"scope="delete""#), "{challenge:?}");
}
