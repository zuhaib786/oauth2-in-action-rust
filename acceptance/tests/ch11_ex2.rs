//! Exercise 11-2: signed JWTs (HS256). Spec: `exercises/ch11-ex2.md`.

use acceptance::*;
use serde_json::Value;

const SHARED_SECRET: &[u8] = b"shared OAuth token secret! (32 bytes or more)";
const BOB_SUB: &str = "1ZT5-OE63-57383B";

#[track_caller]
fn assert_refused(token: &str, what: &str) {
    let reply = get_resource(token);
    assert_eq!(reply.status.as_u16(), 401, "{what}: should be refused, got {}", reply.body);
    let challenge = reply.header("www-authenticate").unwrap_or("");
    assert!(challenge.contains("invalid_token"), "{what}: the challenge should say invalid_token: {challenge:?}");
}

/// Claims the resource would take, for a token the authorization server never issued.
fn good_claims() -> Value {
    let now = now_secs();
    json!({
        "iss": format!("{AS_URL}/"),
        "aud": format!("{RS_URL}/"),
        "sub": BOB_SUB,
        "client_id": CLIENT_ID,
        "scope": "read",
        "iat": now,
        "exp": now + 60,
        "jti": unique("minted"),
    })
}

#[test]
fn r2_unsigned_tokens_are_refused() {
    assert_refused(
        &unsigned_jwt(&json!({ "alg": "none", "typ": "at+jwt" }), &good_claims()),
        "an unsigned token nobody issued",
    );

    // a real token, with its signature taken off
    let token = access_token("foo", "alice");
    let (signing_input, _) = token.rsplit_once('.').unwrap();
    assert_refused(&format!("{signing_input}."), "a real token without its signature");
    let (mut header, claims) = jwt_parts(&token);
    header["alg"] = json!("none");
    assert_refused(&unsigned_jwt(&header, &claims), "a real token's claims under alg none");
}

#[test]
fn r2_tampered_tokens_are_refused() {
    let token = access_token("foo", "alice");
    let (header, claims) = jwt_parts(&token);
    let (_, signature) = token.rsplit_once('.').unwrap();

    let mut more_scope = claims.clone();
    more_scope["scope"] = json!("foo read write delete");
    let tampered = format!("{}{signature}", unsigned_jwt(&header, &more_scope));
    assert_refused(&tampered, "more scope, same signature");

    let hs256 = json!({ "alg": "HS256", "typ": "at+jwt" });
    assert_refused(&hs_jwt(&hs256, &good_claims(), b"another secret, also 32 bytes long"), "the wrong secret");
}

#[test]
fn r3_only_hs256() {
    let claims = good_claims();
    let hs512 = hs_jwt(&json!({ "alg": "HS512", "typ": "at+jwt" }), &claims, SHARED_SECRET);
    assert_refused(&hs512, "HS512, even with the right secret");
}

#[test]
fn r4_signed_tokens_still_need_good_claims() {
    let header = json!({ "alg": "HS256", "typ": "at+jwt" });
    let now = now_secs();
    let with = |key: &str, value: Value| {
        let mut claims = good_claims();
        claims[key] = value;
        hs_jwt(&header, &claims, SHARED_SECRET)
    };
    let without = |key: &str| {
        let mut claims = good_claims();
        claims.as_object_mut().unwrap().remove(key);
        hs_jwt(&header, &claims, SHARED_SECRET)
    };

    for (what, token) in [
        ("expired two minutes ago", with("exp", json!(now - 120))),
        ("no exp", without("exp")),
        ("not valid for another two minutes", with("nbf", json!(now + 120))),
        ("another issuer", with("iss", json!("http://localhost:9999/"))),
        ("no issuer", without("iss")),
        ("another audience", with("aud", json!("http://localhost:9999/"))),
        ("no audience", without("aud")),
        ("typ JWT", hs_jwt(&json!({ "alg": "HS256", "typ": "JWT" }), &good_claims(), SHARED_SECRET)),
        ("no typ", hs_jwt(&json!({ "alg": "HS256" }), &good_claims(), SHARED_SECRET)),
    ] {
        assert_refused(&token, what);
    }
}

// r1_tokens_are_signed_with_hs256 and r5_whoever_has_the_secret_can_mint_tokens
// lived here. 11-3 moved to RS256: see ch11_ex3.rs.
