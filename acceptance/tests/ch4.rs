//! Chapter 4: the protected resource checks tokens and scopes. These are
//! regression tests: later exercises must keep them passing.

use acceptance::*;

#[test]
fn resource_needs_a_valid_token() {
    http().post(format!("{RS_URL}/resource")).call().assert_status(401);
    get_resource("not-a-real-token").assert_status(401);

    let token = access_token("foo", "alice");
    let reply = get_resource(&token);
    reply.assert_status(200);
    assert_eq!(reply.json()["name"], "Protected Resource");
}

#[test]
fn token_in_the_form_body_works() {
    let token = access_token("foo", "alice");
    http()
        .post(format!("{RS_URL}/resource"))
        .form(&[("access_token", token.as_str())])
        .call()
        .assert_status(200);
}

#[test]
fn words_api_checks_scopes() {
    let read_only = access_token("read", "alice");

    http().get(format!("{RS_URL}/words")).bearer_auth(&read_only).call().assert_status(200);

    let add = http()
        .post(format!("{RS_URL}/words"))
        .bearer_auth(&read_only)
        .form(&[("word", "nope")])
        .call();
    add.assert_status(403);
    let challenge = add.header("www-authenticate").unwrap_or("");
    assert!(challenge.contains("insufficient_scope"), "WWW-Authenticate was {challenge:?}");
    assert!(challenge.contains("write"), "WWW-Authenticate should name the missing scope: {challenge:?}");
}

#[test]
fn produce_depends_on_scope() {
    let token = access_token("fruit", "alice");
    let produce = http().get(format!("{RS_URL}/produce")).bearer_auth(&token).call().json();
    assert!(!produce["fruit"].as_array().unwrap().is_empty());
    assert!(produce["veggies"].as_array().unwrap().is_empty());
    assert!(produce["meats"].as_array().unwrap().is_empty());
}

#[test]
fn favorites_depend_on_the_user() {
    for (user, name) in [("alice", "Alice"), ("bob", "Bob")] {
        let token = access_token("movies foods music", user);
        let favorites = http().get(format!("{RS_URL}/favorites")).bearer_auth(&token).call().json();
        assert_eq!(favorites["user"], name);
    }
}
