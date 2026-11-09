//! Exercise 11-3: public-key signatures (RS256) and a JWK Set. Spec: `exercises/ch11-ex3.md`.

use acceptance::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, jwk::JwkSet};
use serde_json::Value;

/// A key the authorization server has never seen.
const OTHER_KEY: &[u8] = include_bytes!("../keys/not-the-servers-key.pem");

#[track_caller]
fn assert_refused(token: &str, what: &str) {
    let reply = get_resource(token);
    assert_eq!(reply.status.as_u16(), 401, "{what}: should be refused, got {}", reply.body);
    let challenge = reply.header("www-authenticate").unwrap_or("");
    assert!(challenge.contains("invalid_token"), "{what}: the challenge should say invalid_token: {challenge:?}");
}

#[track_caller]
fn jwks() -> Value {
    let reply = http().get(format!("{AS_URL}/jwks")).call();
    reply.assert_status(200);
    reply.json()
}

/// Claims the resource would take, for a token the authorization server never issued.
fn good_claims() -> Value {
    let now = now_secs();
    json!({
        "iss": format!("{AS_URL}/"),
        "aud": format!("{RS_URL}/"),
        "sub": "1ZT5-OE63-57383B",
        "client_id": CLIENT_ID,
        "scope": "read",
        "iat": now,
        "exp": now + 60,
        "jti": unique("minted"),
    })
}

/// The `kid` of the authorization server's real tokens.
fn servers_kid() -> String {
    let (header, _) = jwt_parts(&access_token("foo", "alice"));
    header["kid"].as_str().expect("access tokens should name their key with kid").to_string()
}

fn rs256_jwt(kid: Option<&str>, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    header.kid = kid.map(String::from);
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_pem(OTHER_KEY).unwrap()).unwrap()
}

#[test]
fn r2_the_jwks_publishes_public_keys_only() {
    let jwks = jwks();
    let keys = jwks["keys"].as_array().expect(r#"a JWK Set is {"keys": [...]}"#);
    assert!(!keys.is_empty(), "no keys in the JWK Set");
    for key in keys {
        assert_eq!(key["kty"], "RSA", "{key}");
        for field in ["kid", "n", "e"] {
            assert!(key[field].is_string(), "every key needs {field}: {key}");
        }
        for private in ["d", "p", "q", "dp", "dq", "qi"] {
            assert!(key.get(private).is_none(), "the JWK Set gives away the private key ({private})!");
        }
    }
}

#[test]
fn r1_tokens_are_rs256_and_verify_with_the_published_key() {
    let token = access_token("foo", "alice");
    let (header, _) = jwt_parts(&token);
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["typ"], "at+jwt");
    let kid = header["kid"].as_str().expect("access tokens should name their key with kid");

    let set: JwkSet = serde_json::from_value(jwks()).expect("/jwks should be a JWK Set");
    let jwk = set.find(kid).unwrap_or_else(|| panic!("kid {kid:?} isn't in /jwks"));
    let key = DecodingKey::from_jwk(jwk).expect("a usable RSA public key");
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[format!("{AS_URL}/")]);
    validation.set_audience(&[format!("{RS_URL}/")]);
    jsonwebtoken::decode::<Value>(&token, &key, &validation).expect("the signature should verify with the published key");
}

#[test]
fn r3_hs256_is_refused() {
    let kid = servers_kid();
    let header = json!({ "alg": "HS256", "typ": "at+jwt", "kid": kid });
    assert_refused(&hs_jwt(&header, &good_claims(), b"shared OAuth token secret! (32 bytes or more)"), "the old shared secret");

    // Algorithm confusion: the public key is public, so an attacker can use
    // it as an HMAC secret. A resource that lets the header pick the
    // algorithm, and hands it "the key", accepts this.
    let n = jwks()["keys"][0]["n"].as_str().map(|n| URL_SAFE_NO_PAD.decode(n).unwrap()).unwrap();
    assert_refused(&hs_jwt(&header, &good_claims(), &n), "HS256 keyed with the public key");
    let jwk_text = jwks()["keys"][0].to_string();
    assert_refused(&hs_jwt(&header, &good_claims(), jwk_text.as_bytes()), "HS256 keyed with the JWK");
}

#[test]
fn r3_only_the_servers_keys() {
    let kid = servers_kid();
    assert_refused(&rs256_jwt(Some(&kid), &good_claims()), "another key, claiming the server's kid");
    assert_refused(&rs256_jwt(Some("a-kid-nobody-published"), &good_claims()), "an unknown kid");
    assert_refused(&rs256_jwt(None, &good_claims()), "no kid");
}

// What self-contained tokens can't do. 11-4 replaces this test.
#[test]
fn r5_a_revoked_token_still_works() {
    let redeem = |code: &str| {
        token_request(&[("grant_type", "authorization_code"), ("code", code), ("redirect_uri", REDIRECT_URI)])
    };
    let code = get_code("foo", "alice");
    let first = redeem(&code);
    first.assert_status(200);
    redeem(&code).assert_status(400);

    let access_token = first.json()["access_token"].as_str().unwrap().to_string();
    get_resource(&access_token).assert_status(200);
}
