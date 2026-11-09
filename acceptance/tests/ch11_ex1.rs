//! Exercise 11-1: JWT access tokens. Spec: `exercises/ch11-ex1.md`.

use acceptance::*;
use serde_json::Value;

const ALICE_SUB: &str = "9XE3-JI34-00132A";
const BOB_SUB: &str = "1ZT5-OE63-57383B";

fn issuer() -> String {
    format!("{AS_URL}/")
}

fn audience() -> String {
    format!("{RS_URL}/")
}

#[track_caller]
fn claims_of(access_token: &str) -> Value {
    jwt_parts(access_token).1
}

#[track_caller]
fn access_token_of(reply: &Reply) -> String {
    reply.assert_status(200);
    reply.json()["access_token"].as_str().expect("access_token in the token response").to_string()
}

#[track_caller]
fn assert_refused(token: &str, what: &str) {
    let reply = get_resource(token);
    assert_eq!(reply.status.as_u16(), 401, "{what}: should be refused, got {}", reply.body);
    let challenge = reply.header("www-authenticate").unwrap_or("");
    assert!(challenge.contains("invalid_token"), "{what}: the challenge should say invalid_token: {challenge:?}");
}

#[test]
fn r1_access_tokens_are_jwts() {
    let token = access_token("foo bar", "alice");
    let (header, _) = jwt_parts(&token);
    assert_eq!(header["typ"], "at+jwt");
}

#[test]
fn r2_the_claims() {
    let before = now_secs();
    let token = access_token("foo bar", "alice");
    let after = now_secs();
    let claims = claims_of(&token);

    assert_eq!(claims["iss"], issuer().as_str());
    assert_eq!(claims["aud"], audience().as_str());
    assert_eq!(claims["sub"], ALICE_SUB, "sub is the user's sub, not their username");
    assert_eq!(claims["client_id"], CLIENT_ID);
    assert_eq!(scope_set(&claims["scope"]), scope_set("foo bar"));

    let iat = claims["iat"].as_u64().expect("iat should be whole seconds since 1970");
    assert!((before..=after).contains(&iat), "iat {iat} should be now ({before}..={after})");
    assert_eq!(claims["exp"].as_u64(), Some(iat + 300), "exp should be iat + 300");

    let jti = claims["jti"].as_str().expect("jti should be a string");
    let other = claims_of(&access_token("foo bar", "alice"));
    assert_ne!(other["jti"], jti, "every token gets its own jti");
}

#[test]
fn r2_every_grant_issues_jwts() {
    let first = tokens("foo", "alice");
    let refreshed = token_request(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", first["refresh_token"].as_str().unwrap()),
    ]);
    let claims = claims_of(&access_token_of(&refreshed));
    assert_eq!(claims["sub"], ALICE_SUB, "refresh_token grant");
    assert_ne!(claims["jti"], claims_of(first["access_token"].as_str().unwrap())["jti"]);

    let service = token_request_as(
        "oauth-client-service",
        "oauth-client-secret-service",
        &[("grant_type", "client_credentials"), ("scope", "read")],
    );
    let claims = claims_of(&access_token_of(&service));
    assert_eq!(claims["sub"], "oauth-client-service", "client_credentials: no user, so sub is the client");
    assert_eq!(claims["client_id"], "oauth-client-service");

    let password = token_request_as(
        "oauth-client-trusted",
        "oauth-client-secret-trusted",
        &[("grant_type", "password"), ("username", "bob"), ("password", "this is my secret password")],
    );
    let claims = claims_of(&access_token_of(&password));
    assert_eq!(claims["sub"], BOB_SUB, "password grant");
    assert_eq!(claims["client_id"], "oauth-client-trusted");

    let reqid = approval_page(&[
        ("response_type", "token"),
        ("client_id", "oauth-client-implicit"),
        ("redirect_uri", "http://localhost:9000/implicit"),
        ("scope", "foo"),
    ]);
    let back = fragment_params(approve(&reqid, "bob", &["foo"]).location());
    let claims = claims_of(back.get("access_token").expect("access_token in the fragment"));
    assert_eq!(claims["sub"], BOB_SUB, "implicit grant");
    assert_eq!(claims["client_id"], "oauth-client-implicit");
}

#[test]
fn r4_the_resource_checks_the_claims() {
    let (header, claims) = jwt_parts(&access_token("foo", "alice"));
    let now = now_secs();
    let with = |key: &str, value: Value| {
        let mut changed = claims.clone();
        changed[key] = value;
        unsigned_jwt(&header, &changed)
    };
    let without = |key: &str| {
        let mut changed = claims.clone();
        changed.as_object_mut().unwrap().remove(key);
        unsigned_jwt(&header, &changed)
    };

    for (what, token) in [
        ("expired two minutes ago", with("exp", json!(now - 120))),
        ("no exp", without("exp")),
        ("exp isn't a number", with("exp", json!("tomorrow"))),
        ("not valid for another two minutes", with("nbf", json!(now + 120))),
        ("another issuer", with("iss", json!("http://localhost:9999/"))),
        ("the issuer without its slash", with("iss", json!(AS_URL))),
        ("no issuer", without("iss")),
        ("another audience", with("aud", json!("http://localhost:9999/"))),
        ("an audience list without us", with("aud", json!(["http://localhost:9999/"]))),
        ("no audience", without("aud")),
    ] {
        assert_refused(&token, what);
    }
}

#[test]
fn r4_the_resource_checks_the_header() {
    let (header, claims) = jwt_parts(&access_token("foo", "alice"));
    let with = |key: &str, value: Value| {
        let mut changed = header.clone();
        changed[key] = value;
        unsigned_jwt(&changed, &claims)
    };
    let mut no_typ = header.clone();
    no_typ.as_object_mut().unwrap().remove("typ");

    assert_refused(&with("typ", json!("JWT")), "typ JWT: some JWT, not an access token");
    assert_refused(&unsigned_jwt(&no_typ, &claims), "no typ");
    assert_refused(&with("alg", json!("HS256")), "alg HS256 with no signature");
}

#[test]
fn r4_garbage_is_refused_not_a_crash() {
    let (header, claims) = jwt_parts(&access_token("foo", "alice"));
    for (what, token) in [
        ("no dots", "abc".to_string()),
        ("two parts", "abc.def".to_string()),
        ("four parts", format!("{}x.y", unsigned_jwt(&header, &claims))),
        ("parts that aren't base64url", "!!!.???.".to_string()),
        ("parts that aren't JSON", "aGVsbG8.d29ybGQ.".to_string()),
        ("a header that's a JSON array", unsigned_jwt(&json!(["alg", "none"]), &claims)),
        ("claims that are a JSON string", unsigned_jwt(&header, &json!("alice"))),
    ] {
        assert_refused(&token, what);
    }
}

#[test]
fn r5_scope_and_user_come_from_the_token() {
    let read = access_token("read", "bob");
    http().get(format!("{RS_URL}/words")).bearer_auth(&read).call().assert_status(200);
    http().post(format!("{RS_URL}/words")).bearer_auth(&read).form(&[("word", "x")]).call().assert_status(403);

    let favorites = http().get(format!("{RS_URL}/favorites")).bearer_auth(&read).call();
    assert_eq!(favorites.json()["user"], "Bob");
}

// r6_anyone_can_mint_a_token lived here. 11-2 turned it around: see
// r2_unsigned_tokens_are_refused in ch11_ex2.rs.
