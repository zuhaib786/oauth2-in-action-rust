//! Exercise 11-4: token introspection. Spec: `exercises/ch11-ex4.md`.

use acceptance::*;
use serde_json::Value;

const RESOURCE_ID: &str = "protected-resource-1";
const RESOURCE_SECRET: &str = "protected-resource-secret-1";
const ALICE_SUB: &str = "9XE3-JI34-00132A";

fn introspect_as(id: &str, secret: &str, form: &[(&str, &str)]) -> Reply {
    http().post(format!("{AS_URL}/introspect")).basic_auth(id, Some(secret)).form(form).call()
}

#[track_caller]
fn introspect(token: &str) -> Value {
    let reply = introspect_as(RESOURCE_ID, RESOURCE_SECRET, &[("token", token)]);
    reply.assert_status(200);
    reply.json()
}

#[track_caller]
fn assert_inactive(answer: &Value, what: &str) {
    assert_eq!(*answer, json!({ "active": false }), "{what}: an inactive token gets {{\"active\": false}} and nothing else");
}

fn redeem(code: &str) -> Reply {
    token_request(&[("grant_type", "authorization_code"), ("code", code), ("redirect_uri", REDIRECT_URI)])
}

#[test]
fn r1_only_protected_resources_may_ask() {
    let token = access_token("foo", "alice");
    let anonymous = http().post(format!("{AS_URL}/introspect")).form(&[("token", token.as_str())]).call();
    assert_eq!(anonymous.status.as_u16(), 401, "no credentials");

    for (id, secret, what) in [
        (RESOURCE_ID, "not-the-secret", "the wrong secret"),
        (CLIENT_ID, CLIENT_SECRET, "a client's credentials"),
    ] {
        let reply = introspect_as(id, secret, &[("token", &token)]);
        assert_eq!(reply.status.as_u16(), 401, "{what}: {}", reply.body);
        assert!(!reply.body.contains("active"), "{what}: must not say anything about the token");
    }
}

#[test]
fn r2_an_active_token() {
    let before = now_secs();
    let token = access_token("foo bar", "alice");
    let answer = introspect(&token);

    assert_eq!(answer["active"], true, "{answer}");
    assert_eq!(answer["sub"], ALICE_SUB);
    assert_eq!(answer["client_id"], CLIENT_ID);
    assert_eq!(scope_set(&answer["scope"]), scope_set("foo bar"));
    assert_eq!(answer["iss"], format!("{AS_URL}/").as_str());
    let exp = answer["exp"].as_u64().expect("exp, in seconds since 1970");
    assert!(exp > before, "exp is in the future");

    // the hint is only a hint (RFC 7662 §2.1)
    let hinted = introspect_as(RESOURCE_ID, RESOURCE_SECRET, &[("token", &token), ("token_type_hint", "refresh_token")]);
    assert_eq!(hinted.json()["active"], true, "a wrong token_type_hint mustn't change the answer");
}

#[test]
fn r2_inactive_tokens() {
    assert_inactive(&introspect("not-a-token"), "garbage");
    assert_inactive(&introspect(""), "an empty token");

    // a real token with its claims changed
    let token = access_token("foo", "alice");
    let (header, mut claims) = jwt_parts(&token);
    claims["scope"] = json!("foo read write delete");
    let (_, signature) = token.rsplit_once('.').unwrap();
    assert_inactive(&introspect(&format!("{}{signature}", unsigned_jwt(&header, &claims))), "a tampered token");
}

#[test]
fn r3_revoked_tokens_are_inactive() {
    let code = get_code("foo", "alice");
    let first = redeem(&code);
    first.assert_status(200);
    let access_token = first.json()["access_token"].as_str().unwrap().to_string();
    let refreshed = token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", first.json()["refresh_token"].as_str().unwrap()),
    ]);
    let refreshed_access_token = refreshed.json()["access_token"].as_str().unwrap().to_string();
    assert_eq!(introspect(&access_token)["active"], true);

    redeem(&code).assert_status(400);

    assert_inactive(&introspect(&access_token), "the access token from a replayed code");
    assert_inactive(&introspect(&refreshed_access_token), "an access token refreshed from it");
}

#[test]
fn r4_a_resource_only_hears_about_its_own_tokens() {
    let token = access_token("foo", "alice");
    let reply = introspect_as("protected-resource-2", "protected-resource-secret-2", &[("token", &token)]);
    reply.assert_status(200);
    assert_inactive(&reply.json(), "asked by a resource the token isn't for");
}

#[test]
fn r5_the_resource_refuses_revoked_tokens() {
    let code = get_code("foo", "alice");
    let first = redeem(&code);
    let access_token = first.json()["access_token"].as_str().unwrap().to_string();
    get_resource(&access_token).assert_status(200);

    redeem(&code).assert_status(400);

    let reply = get_resource(&access_token);
    assert_eq!(reply.status.as_u16(), 401, "the token's grant was revoked: {}", reply.body);
    assert!(reply.header("www-authenticate").unwrap_or("").contains("invalid_token"));
}
