//! Exercise 15-1: DPoP, sender-constrained tokens. Spec: `exercises/ch15-ex1.md`.

use acceptance::*;
use serde_json::Value;

const SERVICE_ID: &str = "oauth-client-service";
const SERVICE_SECRET: &str = "oauth-client-secret-service";
const NATIVE_ID: &str = "oauth-native-client";
const NATIVE_REDIRECT_URI: &str = "http://127.0.0.1:53125/callback";

fn token_endpoint() -> String {
    format!("{AS_URL}/token")
}

fn resource_url() -> String {
    format!("{RS_URL}/resource")
}

/// A client credentials token for the service client, with a DPoP proof if given.
fn service_token(proof: Option<&str>) -> Reply {
    let mut request = http()
        .post(token_endpoint())
        .basic_auth(SERVICE_ID, Some(SERVICE_SECRET))
        .form(&[("grant_type", "client_credentials"), ("scope", "read")]);
    if let Some(proof) = proof {
        request = request.header("DPoP", proof);
    }
    request.call()
}

/// A token bound to this key.
#[track_caller]
fn bound_token(key: &DpopKey) -> String {
    let reply = service_token(Some(&key.proof("POST", &token_endpoint(), None)));
    reply.assert_status(200);
    reply.json()["access_token"].as_str().unwrap().to_string()
}

fn call_resource(scheme: &str, token: &str, proof: Option<&str>) -> Reply {
    let mut request = http().post(resource_url()).header("Authorization", format!("{scheme} {token}"));
    if let Some(proof) = proof {
        request = request.header("DPoP", proof);
    }
    request.call()
}

fn token_type(tokens: &Value) -> String {
    tokens["token_type"].as_str().unwrap_or("").to_ascii_lowercase()
}

#[test]
fn r1_a_proof_gets_a_bound_token() {
    let key = DpopKey::generate();
    let reply = service_token(Some(&key.proof("POST", &token_endpoint(), None)));
    reply.assert_status(200);
    let tokens = reply.json();
    assert_eq!(token_type(&tokens), "dpop", "{tokens}");
    let (_, claims) = jwt_parts(tokens["access_token"].as_str().unwrap());
    assert_eq!(claims["cnf"]["jkt"], key.thumbprint().as_str(), "the token is bound to the proof's key");
}

#[test]
fn r1_no_proof_a_bearer_token() {
    let reply = service_token(None);
    reply.assert_status(200);
    let tokens = reply.json();
    assert_eq!(token_type(&tokens), "bearer");
    let (_, claims) = jwt_parts(tokens["access_token"].as_str().unwrap());
    assert!(claims.get("cnf").is_none(), "an unbound token: {claims}");
}

#[test]
fn r2_bad_proofs_at_the_token_endpoint() {
    let key = DpopKey::generate();
    let now = now_secs();
    let claims = |htm: &str, htu: &str, iat: u64| json!({ "jti": random_id(), "htm": htm, "htu": htu, "iat": iat });
    let good = || claims("POST", &token_endpoint(), now);
    let header_with = |name: &str, value: Value| {
        let mut header = key.proof_header();
        header[name] = value;
        header
    };
    let mut with_private_key = key.proof_header();
    with_private_key["jwk"]["d"] = json!("bm90IHJlYWxseSBhIHByaXZhdGUga2V5");
    let mut no_jti = good();
    no_jti.as_object_mut().unwrap().remove("jti");

    for (what, proof) in [
        ("not a JWT", "not-a-proof".to_string()),
        ("for another method", key.sign(&key.proof_header(), &claims("GET", &token_endpoint(), now))),
        ("for another URL", key.sign(&key.proof_header(), &claims("POST", &format!("{AS_URL}/elsewhere"), now))),
        ("ten minutes old", key.sign(&key.proof_header(), &claims("POST", &token_endpoint(), now - 600))),
        ("ten minutes ahead", key.sign(&key.proof_header(), &claims("POST", &token_endpoint(), now + 600))),
        ("without a jti", key.sign(&key.proof_header(), &no_jti)),
        ("typ JWT", key.sign(&header_with("typ", json!("JWT")), &good())),
        ("alg HS256", key.sign(&header_with("alg", json!("HS256")), &good())),
        ("without a jwk", key.sign(&json!({ "typ": "dpop+jwt", "alg": "ES256" }), &good())),
        ("unsigned", unsigned_jwt(&header_with("alg", json!("none")), &good())),
        ("signed by another key than its jwk", DpopKey::generate().sign(&key.proof_header(), &good())),
        ("a jwk with a private key in it", key.sign(&with_private_key, &good())),
    ] {
        let reply = service_token(Some(&proof));
        assert_eq!(reply.status.as_u16(), 400, "{what}: {}", reply.body);
        assert_eq!(error_code(&reply), "invalid_dpop_proof", "{what}");
    }
}

#[test]
fn r2_a_proof_works_once() {
    let key = DpopKey::generate();
    let proof = key.proof("POST", &token_endpoint(), None);
    service_token(Some(&proof)).assert_status(200);
    let replay = service_token(Some(&proof));
    assert_eq!(replay.status.as_u16(), 400, "a replayed proof: {}", replay.body);
    assert_eq!(error_code(&replay), "invalid_dpop_proof");
}

/// The native client's code flow, with PKCE, traded with a proof by this key.
#[track_caller]
fn native_tokens(key: &DpopKey) -> Value {
    let (verifier, challenge) = pkce_pair();
    let reqid = approval_page(&[
        ("response_type", "code"),
        ("client_id", NATIVE_ID),
        ("redirect_uri", NATIVE_REDIRECT_URI),
        ("scope", "foo"),
        ("state", "st-dpop"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let code = query_params(approve(&reqid, "alice", &["foo"]).location())["code"].clone();
    let reply = http()
        .post(token_endpoint())
        .header("DPoP", key.proof("POST", &token_endpoint(), None))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", NATIVE_ID),
            ("code", &code),
            ("redirect_uri", NATIVE_REDIRECT_URI),
            ("code_verifier", &verifier),
        ])
        .call();
    reply.assert_status(200);
    reply.json()
}

/// grant_type=refresh_token with these client credentials (none for a public client) and proof.
fn refresh(client: (&str, Option<&str>), refresh_token: &str, proof: Option<String>) -> Reply {
    let (client_id, secret) = client;
    let mut request = http().post(token_endpoint());
    let mut form = vec![("grant_type", "refresh_token"), ("refresh_token", refresh_token)];
    match secret {
        Some(secret) => request = request.basic_auth(client_id, Some(secret)),
        None => form.push(("client_id", client_id)),
    }
    if let Some(proof) = proof {
        request = request.header("DPoP", proof);
    }
    request.form(&form).call()
}

#[test]
fn r2_a_public_clients_refresh_token_is_bound() {
    let key = DpopKey::generate();
    let refresh_token = native_tokens(&key)["refresh_token"].as_str().unwrap().to_string();
    let native = (NATIVE_ID, None);

    let without = refresh(native, &refresh_token, None);
    assert_eq!(without.status.as_u16(), 400, "a bound refresh token without a proof: {}", without.body);
    let other_key = refresh(native, &refresh_token, Some(DpopKey::generate().proof("POST", &token_endpoint(), None)));
    assert_eq!(other_key.status.as_u16(), 400, "a bound refresh token with another key's proof: {}", other_key.body);

    // the failed tries above didn't use it up
    let same_key = refresh(native, &refresh_token, Some(key.proof("POST", &token_endpoint(), None)));
    same_key.assert_status(200);
    let tokens = same_key.json();
    assert_eq!(token_type(&tokens), "dpop");
    let (_, claims) = jwt_parts(tokens["access_token"].as_str().unwrap());
    assert_eq!(claims["cnf"]["jkt"], key.thumbprint().as_str());
}

#[test]
fn r2_a_confidential_clients_refresh_token_is_not() {
    let first_key = DpopKey::generate();
    let code = get_code("foo", "alice");
    let reply = http()
        .post(token_endpoint())
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .header("DPoP", first_key.proof("POST", &token_endpoint(), None))
        .form(&[("grant_type", "authorization_code"), ("code", &code), ("redirect_uri", REDIRECT_URI)])
        .call();
    reply.assert_status(200);
    let refresh_token = reply.json()["refresh_token"].as_str().unwrap().to_string();

    // client authentication already ties it to the client, which may move to a new key
    let new_key = DpopKey::generate();
    let reply = refresh((CLIENT_ID, Some(CLIENT_SECRET)), &refresh_token, Some(new_key.proof("POST", &token_endpoint(), None)));
    reply.assert_status(200);
    let (_, claims) = jwt_parts(reply.json()["access_token"].as_str().unwrap());
    assert_eq!(claims["cnf"]["jkt"], new_key.thumbprint().as_str(), "bound to the key of this request's proof");
}

#[test]
fn r3_the_resource_wants_the_proof() {
    let key = DpopKey::generate();
    let token = bound_token(&key);
    let url = resource_url();

    call_resource("DPoP", &token, Some(&key.proof("POST", &url, Some(&token)))).assert_status(200);

    let as_bearer = call_resource("Bearer", &token, None);
    assert_eq!(as_bearer.status.as_u16(), 401, "a bound token used as a bearer token: {}", as_bearer.body);

    for (what, proof) in [
        ("no proof", None),
        ("a proof by another key", Some(DpopKey::generate().proof("POST", &url, Some(&token)))),
        ("a proof for another token", Some(key.proof("POST", &url, Some("some-other-token")))),
        ("a proof without ath", Some(key.proof("POST", &url, None))),
        ("a proof for another URL", Some(key.proof("POST", &format!("{RS_URL}/words"), Some(&token)))),
        ("a proof for another method", Some(key.proof("GET", &url, Some(&token)))),
    ] {
        let reply = call_resource("DPoP", &token, proof.as_deref());
        assert_eq!(reply.status.as_u16(), 401, "{what}: {}", reply.body);
        let challenge = reply.header("www-authenticate").unwrap_or("");
        assert!(challenge.starts_with("DPoP"), "{what}: a DPoP challenge, got {challenge:?}");
    }
}

#[test]
fn r3_a_proof_works_once_at_the_resource_too() {
    let key = DpopKey::generate();
    let token = bound_token(&key);
    let proof = key.proof("POST", &resource_url(), Some(&token));
    call_resource("DPoP", &token, Some(&proof)).assert_status(200);
    let replay = call_resource("DPoP", &token, Some(&proof));
    assert_eq!(replay.status.as_u16(), 401, "a replayed proof: {}", replay.body);
}

#[test]
fn r3_htu_has_no_query() {
    let key = DpopKey::generate();
    let token = bound_token(&key);
    let reply = http()
        .get(format!("{RS_URL}/helloWorld?language=en"))
        .header("Authorization", format!("DPoP {token}"))
        .header("DPoP", key.proof("GET", &format!("{RS_URL}/helloWorld"), Some(&token)))
        .call();
    reply.assert_status(200);
    assert_eq!(reply.json()["greeting"], "Hello World");
}

#[test]
fn r4_the_native_client_uses_dpop() {
    let mut app = Running::start(&build_bin("native-client"), &[]);
    let url = app.wait_for_line("the authorization URL", |line| line.trim().starts_with(&format!("{AS_URL}/authorize?")));
    let page = http().get(url.trim()).call();
    let back = approve(&reqid(&page.body), "alice", &["foo", "bar"]);
    http().get(back.location()).call().assert_status(200);

    let (status, stdout) = app.wait_for_exit();
    assert!(status.success(), "native-client failed ({status}). stdout:\n{stdout}");
    assert!(stdout.contains("Token type: DPoP"), "stdout:\n{stdout}");
    assert!(stdout.contains("Protected Resource"), "stdout:\n{stdout}");
}
