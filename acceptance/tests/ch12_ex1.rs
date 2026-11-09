//! Exercise 12-1: dynamic client registration. Spec: `exercises/ch12-ex1.md`.

use acceptance::*;
use serde_json::Value;

const APP_CALLBACK: &str = "https://app.example.com/callback";

fn register(metadata: &Value) -> Reply {
    http().post(format!("{AS_URL}/register")).json(metadata).call()
}

#[track_caller]
fn registered(metadata: &Value) -> Value {
    let reply = register(metadata);
    assert_eq!(reply.status.as_u16(), 201, "registering {metadata}: {}", reply.body);
    reply.json()
}

fn field(registration: &Value, name: &str) -> String {
    registration[name].as_str().unwrap_or_else(|| panic!("no {name} in {registration}")).to_string()
}

#[track_caller]
fn assert_refused(metadata: &Value, error: &str, what: &str) {
    let reply = register(metadata);
    assert_eq!(reply.status.as_u16(), 400, "{what}: should be refused, got {}", reply.body);
    assert_eq!(error_code(&reply), error, "{what}");
}

fn code_for(client_id: &str, redirect_uri: &str, extra: &[(&str, &str)]) -> String {
    let mut request = vec![
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("scope", "foo"),
        ("state", "st"),
    ];
    request.extend_from_slice(extra);
    let reqid = approval_page(&request);
    query_params(approve(&reqid, "alice", &["foo"]).location())["code"].clone()
}

#[test]
fn r1_registering_a_client() {
    let before = now_secs();
    let metadata = json!({
        "client_name": "Test client",
        "redirect_uris": [APP_CALLBACK],
        "scope": "foo bar",
    });
    let client = registered(&metadata);

    let secret = field(&client, "client_secret");
    assert!(secret.len() >= 22, "a secret needs at least 128 bits of randomness: {secret}");
    let issued_at = client["client_id_issued_at"].as_u64().expect("client_id_issued_at, in seconds since 1970");
    assert!(issued_at >= before);
    assert_eq!(client["client_secret_expires_at"], 0, "0 means the secret doesn't expire");

    assert_eq!(client["token_endpoint_auth_method"], "client_secret_basic", "the default");
    assert_eq!(client["grant_types"], json!(["authorization_code"]), "the default");
    assert_eq!(client["response_types"], json!(["code"]), "the default");
    assert_eq!(client["redirect_uris"], json!([APP_CALLBACK]));
    assert_eq!(client["client_name"], "Test client");
    assert_eq!(scope_set(&client["scope"]), scope_set("foo bar"));

    assert_ne!(registered(&metadata)["client_id"], client["client_id"], "every registration gets its own client_id");
}

#[test]
fn r1_the_answer_is_not_cached() {
    let reply = register(&json!({ "redirect_uris": [APP_CALLBACK] }));
    reply.assert_status(201);
    assert_eq!(reply.header("cache-control"), Some("no-store"), "the answer holds a secret");
}

#[test]
fn r2_a_registered_client_can_log_in() {
    let client = registered(&json!({
        "redirect_uris": [APP_CALLBACK],
        "scope": "foo bar",
        "grant_types": ["authorization_code", "refresh_token"],
    }));
    let (id, secret) = (field(&client, "client_id"), field(&client, "client_secret"));

    let code = code_for(&id, APP_CALLBACK, &[]);
    let tokens = token_request_as(&id, &secret, &[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", APP_CALLBACK),
    ]);
    tokens.assert_status(200);
    get_resource(tokens.json()["access_token"].as_str().unwrap()).assert_status(200);

    let refresh_token = tokens.json()["refresh_token"].as_str().expect("registered for refresh_token").to_string();
    token_request_as(&id, &secret, &[("grant_type", "refresh_token"), ("refresh_token", &refresh_token)])
        .assert_status(200);
}

#[test]
fn r2_public_clients() {
    let client = registered(&json!({
        "redirect_uris": ["http://127.0.0.1/callback"],
        "token_endpoint_auth_method": "none",
        "scope": "foo",
    }));
    assert!(client.get("client_secret").is_none(), "a public client gets no secret: {client}");
    let id = field(&client, "client_id");

    let redirect_uri = "http://127.0.0.1:4567/callback";
    let (verifier, challenge) = pkce_pair();
    let code = code_for(&id, redirect_uri, &[("code_challenge", &challenge), ("code_challenge_method", "S256")]);
    token_request_form(&[
        ("client_id", &id),
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", &verifier),
    ])
    .assert_status(200);
}

#[test]
fn r2_service_clients() {
    let client = registered(&json!({ "grant_types": ["client_credentials"], "scope": "read" }));
    assert_eq!(client["response_types"], json!([]), "no authorization endpoint, so no response types");
    let reply = token_request_as(&field(&client, "client_id"), &field(&client, "client_secret"), &[
        ("grant_type", "client_credentials"),
        ("scope", "read"),
    ]);
    reply.assert_status(200);
}

#[test]
fn r2_the_approval_page_shows_the_name_safely() {
    let client = registered(&json!({
        "client_name": "<script>alert('pwned')</script>",
        "redirect_uris": [APP_CALLBACK],
        "scope": "foo",
    }));
    let page = authorize(&[
        ("response_type", "code"),
        ("client_id", &field(&client, "client_id")),
        ("redirect_uri", APP_CALLBACK),
        ("scope", "foo"),
    ]);
    page.assert_status(200);
    assert!(!page.body.contains("<script>alert"), "the client's name went into the page unescaped");
    assert!(page.body.contains("&lt;script&gt;alert("), "the approval page should show the client's name");
}

#[test]
fn r3_bad_redirect_uris() {
    for (what, metadata) in [
        ("none, for the code grant", json!({ "scope": "foo" })),
        ("an empty list", json!({ "redirect_uris": [] })),
        ("not a URL", json!({ "redirect_uris": ["not a url"] })),
        ("javascript:", json!({ "redirect_uris": ["javascript:alert(1)"] })),
        ("data:", json!({ "redirect_uris": ["data:text/html,hello"] })),
        ("a fragment", json!({ "redirect_uris": ["https://app.example.com/callback#here"] })),
        ("plain http to a public host", json!({ "redirect_uris": ["http://app.example.com/callback"] })),
        ("one good, one bad", json!({ "redirect_uris": [APP_CALLBACK, "javascript:alert(1)"] })),
    ] {
        assert_refused(&metadata, "invalid_redirect_uri", what);
    }
}

#[test]
fn r4_bad_metadata() {
    let uris = json!([APP_CALLBACK]);
    for (what, metadata) in [
        ("the password grant", json!({ "redirect_uris": uris, "grant_types": ["authorization_code", "password"] })),
        ("the implicit grant", json!({ "redirect_uris": uris, "grant_types": ["implicit"], "response_types": ["token"] })),
        ("an unknown grant type", json!({ "redirect_uris": uris, "grant_types": ["magic"] })),
        ("response type token", json!({ "redirect_uris": uris, "response_types": ["token"] })),
        ("code without authorization_code", json!({ "grant_types": ["client_credentials"], "response_types": ["code"] })),
        ("authorization_code without code", json!({ "redirect_uris": uris, "response_types": [] })),
        ("an unsupported auth method", json!({ "redirect_uris": uris, "token_endpoint_auth_method": "private_key_jwt" })),
        (
            "client credentials for a public client",
            json!({ "grant_types": ["client_credentials"], "token_endpoint_auth_method": "none" }),
        ),
        ("a scope the server doesn't have", json!({ "redirect_uris": uris, "scope": "foo nuclear-launch" })),
        ("a javascript: client_uri", json!({ "redirect_uris": uris, "client_uri": "javascript:alert(1)" })),
        ("a javascript: logo_uri", json!({ "redirect_uris": uris, "logo_uri": "javascript:alert(1)" })),
        ("grant_types isn't a list", json!({ "redirect_uris": uris, "grant_types": "authorization_code" })),
    ] {
        assert_refused(&metadata, "invalid_client_metadata", what);
    }
}

#[test]
fn r4_not_json() {
    let reply = http()
        .post(format!("{AS_URL}/register"))
        .header("content-type", "application/json")
        .body("{\"redirect_uris\": [")
        .call();
    assert_eq!(reply.status.as_u16(), 400, "{}", reply.body);
    assert_eq!(error_code(&reply), "invalid_client_metadata");
}

#[test]
fn r5_clients_authenticate_the_way_they_registered() {
    let post = registered(&json!({
        "grant_types": ["client_credentials"],
        "scope": "read",
        "token_endpoint_auth_method": "client_secret_post",
    }));
    let (id, secret) = (field(&post, "client_id"), field(&post, "client_secret"));
    let form = [("grant_type", "client_credentials")];
    let mut in_body = form.to_vec();
    in_body.extend([("client_id", id.as_str()), ("client_secret", secret.as_str())]);

    token_request_form(&in_body).assert_status(200);
    let basic = token_request_as(&id, &secret, &form);
    assert_eq!(basic.status.as_u16(), 401, "registered for client_secret_post, used Basic");
    assert_eq!(error_code(&basic), "invalid_client");

    let basic_client = registered(&json!({ "grant_types": ["client_credentials"], "scope": "read" }));
    let (id, secret) = (field(&basic_client, "client_id"), field(&basic_client, "client_secret"));
    token_request_as(&id, &secret, &form).assert_status(200);
    let mut in_body = form.to_vec();
    in_body.extend([("client_id", id.as_str()), ("client_secret", secret.as_str())]);
    let post = token_request_form(&in_body);
    assert_eq!(post.status.as_u16(), 401, "registered for client_secret_basic (the default), used the body");
}

#[test]
fn r6_no_secrets_on_the_home_page() {
    let client = registered(&json!({ "redirect_uris": [APP_CALLBACK] }));
    let home = http().get(format!("{AS_URL}/")).call();
    home.assert_status(200);
    assert!(!home.body.contains(&field(&client, "client_secret")), "anyone can read the home page");
    assert!(!home.body.contains(CLIENT_SECRET), "not even the built-in clients' secrets");
}

#[test]
fn r7_the_web_client_registers_itself() {
    let _turn = client_app_lock();
    let (alice, bob) = (browser(), browser());
    let alice_id = query_params(&client_authorize_url(&alice))["client_id"].clone();
    assert_ne!(alice_id, CLIENT_ID, "the web client should use a client_id it registered");
    let bob_id = query_params(&client_authorize_url(&bob))["client_id"].clone();
    assert_eq!(alice_id, bob_id, "it registers once, not once per login");

    client_login(&alice, "alice", None).assert_status(303);
    assert!(client_shown_token(&alice).is_some(), "logging in with the registered client should work");
}

#[test]
fn r8_the_client_refreshes_with_its_registration() {
    let _turn = client_app_lock();
    let bob = browser();
    client_login(&bob, "bob", None).assert_status(303);

    // twice: the second refresh only works if the client kept the rotated refresh token (11-5)
    for round in 1..=2 {
        let old = client_shown_token(&bob).expect("the client should hold a token");
        let reply = bob.post(format!("{CLIENT_URL}/refresh")).call();
        assert_eq!(reply.status.as_u16(), 303, "round {round}: {}", reply.body);
        assert_eq!(reply.location(), "/");
        let new = client_shown_token(&bob).expect("the client should still hold a token");
        assert_ne!(new, old, "round {round}: the client should have a new access token");
        get_resource(&new).assert_status(200);
    }
}
