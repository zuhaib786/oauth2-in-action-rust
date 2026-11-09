//! Exercise 13-1: OpenID Connect. Spec: `exercises/ch13-ex1.md`.

use acceptance::*;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use serde_json::Value;

const ALICE_SUB: &str = "9XE3-JI34-00132A";

#[track_caller]
fn discovery() -> Value {
    let reply = http().get(format!("{AS_URL}/.well-known/openid-configuration")).call();
    reply.assert_status(200);
    reply.json()
}

/// A code-flow token response for oauth-client-1, with these extra
/// authorization request parameters.
#[track_caller]
fn tokens_with(extra: &[(&str, &str)], scope: &str, user: &str) -> Value {
    let code = get_code_with(extra, scope, user);
    let reply = token_request(&[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT_URI)]);
    reply.assert_status(200);
    reply.json()
}

/// Checks an ID token's signature against the published keys and returns its claims.
#[track_caller]
fn verified_id_token(id_token: &str) -> Value {
    let (header, _) = jwt_parts(id_token);
    assert_eq!(header["alg"], "RS256");
    let kid = header["kid"].as_str().expect("an ID token should name its key with kid");
    let jwks = http().get(format!("{AS_URL}/jwks")).call().json();
    let set: JwkSet = serde_json::from_value(jwks).unwrap();
    let key = DecodingKey::from_jwk(set.find(kid).expect("the kid should be in /jwks")).unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[format!("{AS_URL}/")]);
    validation.set_audience(&[CLIENT_ID]);
    validation.set_required_spec_claims(&["iss", "sub", "aud", "exp", "iat"]);
    jsonwebtoken::decode::<Value>(id_token, &key, &validation).expect("the ID token should verify").claims
}

fn userinfo(access_token: &str) -> Reply {
    http().get(format!("{AS_URL}/userinfo")).bearer_auth(access_token).call()
}

#[test]
fn r1_discovery() {
    let config = discovery();
    assert_eq!(config["issuer"], format!("{AS_URL}/").as_str());
    for (name, path) in [
        ("authorization_endpoint", "/authorize"),
        ("token_endpoint", "/token"),
        ("userinfo_endpoint", "/userinfo"),
        ("jwks_uri", "/jwks"),
        ("registration_endpoint", "/register"),
    ] {
        assert_eq!(config[name], format!("{AS_URL}{path}").as_str(), "{name}");
    }
    let has = |name: &str, value: &str| config[name].as_array().is_some_and(|values| values.iter().any(|v| v == value));
    assert!(has("scopes_supported", "openid"), "scopes_supported: {config}");
    assert!(has("response_types_supported", "code"));
    assert!(has("subject_types_supported", "public"));
    assert_eq!(config["id_token_signing_alg_values_supported"], json!(["RS256"]));
    assert_eq!(config["code_challenge_methods_supported"], json!(["S256"]));
}

#[test]
fn r2_openid_gets_an_id_token() {
    let before = now_secs();
    let tokens = tokens_with(&[("nonce", "n-0S6_WzA2Mj")], "openid foo", "alice");
    let id_token = tokens["id_token"].as_str().expect("scope openid should get an id_token");
    let claims = verified_id_token(id_token);

    assert_eq!(claims["sub"], ALICE_SUB);
    assert_eq!(claims["nonce"], "n-0S6_WzA2Mj", "the nonce from the authorization request");
    let iat = claims["iat"].as_u64().unwrap();
    assert!(iat >= before && iat <= now_secs(), "iat should be now");
    assert!(claims["exp"].as_u64().unwrap() > iat);

    let without_nonce = tokens_with(&[], "openid", "alice");
    let claims = verified_id_token(without_nonce["id_token"].as_str().unwrap());
    assert!(claims.get("nonce").is_none(), "no nonce asked for, none in the token");
}

#[test]
fn r2_no_openid_no_id_token() {
    let tokens = tokens("foo", "alice");
    assert!(tokens.get("id_token").is_none(), "an id_token without scope openid: {tokens}");
}

#[test]
fn r2_an_id_token_is_not_an_access_token() {
    let tokens = tokens_with(&[], "openid foo", "alice");
    let reply = get_resource(tokens["id_token"].as_str().unwrap());
    assert_eq!(reply.status.as_u16(), 401, "the resource took an ID token as an access token");
}

#[test]
fn r3_userinfo_by_scope() {
    let everything = access_token("openid profile email", "alice");
    let reply = userinfo(&everything);
    reply.assert_status(200);
    let info = reply.json();
    assert_eq!(info["sub"], ALICE_SUB);
    assert_eq!(info["name"], "Alice");
    assert_eq!(info["preferred_username"], "alice");
    assert_eq!(info["email"], "alice.wonderland@example.com");
    assert_eq!(info["email_verified"], true);

    let just_openid = userinfo(&access_token("openid", "alice")).json();
    assert_eq!(just_openid["sub"], ALICE_SUB);
    for claim in ["name", "preferred_username", "email", "email_verified"] {
        assert!(just_openid.get(claim).is_none(), "{claim} needs the profile or email scope: {just_openid}");
    }

    let post = http().post(format!("{AS_URL}/userinfo")).bearer_auth(&everything).call();
    post.assert_status(200);
    assert_eq!(post.json()["sub"], ALICE_SUB, "userinfo answers POST too");
}

#[test]
fn r3_userinfo_needs_an_openid_token() {
    let no_token = http().get(format!("{AS_URL}/userinfo")).call();
    assert_eq!(no_token.status.as_u16(), 401);

    let garbage = userinfo("not-a-token");
    assert_eq!(garbage.status.as_u16(), 401);
    assert!(garbage.header("www-authenticate").unwrap_or("").contains("invalid_token"));

    let not_openid = userinfo(&access_token("foo", "alice"));
    assert_eq!(not_openid.status.as_u16(), 403, "a token without scope openid: {}", not_openid.body);
    assert!(not_openid.header("www-authenticate").unwrap_or("").contains("insufficient_scope"));

    let tokens = tokens_with(&[], "openid profile", "alice");
    let id_token = tokens["id_token"].as_str().unwrap();
    assert_eq!(userinfo(id_token).status.as_u16(), 401, "an ID token is not an access token");

    let access_token = tokens["access_token"].as_str().unwrap();
    userinfo(access_token).assert_status(200);
    http()
        .post(format!("{AS_URL}/revoke"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .form(&[("token", access_token)])
        .call()
        .assert_status(200);
    assert_eq!(userinfo(access_token).status.as_u16(), 401, "a revoked token");
}

#[test]
fn r4_the_web_client_asks_for_openid_with_a_nonce() {
    let _turn = client_app_lock();
    let alice = browser();
    let first = query_params(&client_authorize_url(&alice));
    let second = query_params(&client_authorize_url(&alice));
    assert!(first.get("scope").is_some_and(|scope| scope.split(' ').any(|s| s == "openid")), "{first:?}");
    let nonce = first.get("nonce").expect("the web client should send a nonce");
    assert!(nonce.len() >= 22, "a nonce needs at least 128 bits of randomness: {nonce}");
    assert_ne!(first.get("nonce"), second.get("nonce"), "a fresh nonce for every login");
}

#[test]
fn r4_the_web_client_knows_who_logged_in() {
    let _turn = client_app_lock();
    for (user, name) in [("alice", "Alice"), ("bob", "Bob")] {
        let browser = browser();
        client_login(&browser, user, None).assert_status(303);
        let home = browser.get(format!("{CLIENT_URL}/")).call();
        assert!(home.body.contains(&format!("Logged in as {name}")), "{user}'s home page:\n{}", home.body);
    }
}
