//! Exercise 8-2: CORS. Spec: `exercises/ch8-ex2.md`.

use acceptance::*;
use reqwest::Method;

const EVIL: &str = "http://evil.example";

fn preflight(origin: &str, method: &str) -> Reply {
    http()
        .request(Method::OPTIONS, format!("{RS_URL}/resource"))
        .header("origin", origin)
        .header("access-control-request-method", method)
        .header("access-control-request-headers", "authorization,content-type")
        .call()
}

fn lower(value: Option<&str>) -> String {
    value.unwrap_or("").to_ascii_lowercase()
}

#[test]
fn r1_r3_r5_the_client_app_may_preflight() {
    for method in ["GET", "POST", "DELETE"] {
        let reply = preflight(CLIENT_URL, method);
        assert!(reply.status.is_success(), "preflight for {method} got {}", reply.status);
        assert_eq!(reply.header("access-control-allow-origin"), Some(CLIENT_URL));
        assert!(lower(reply.header("access-control-allow-methods")).contains(&method.to_ascii_lowercase()), "{method}");
        let headers = lower(reply.header("access-control-allow-headers"));
        assert!(headers.contains("authorization") && headers.contains("content-type"), "allow-headers was {headers:?}");
        assert_eq!(reply.header("access-control-max-age"), Some("600"));
    }
}

#[test]
fn r2_other_origins_get_nothing() {
    let reply = preflight(EVIL, "POST");
    assert_eq!(reply.header("access-control-allow-origin"), None, "no CORS for {EVIL}");

    let token = access_token("foo", "alice");
    let actual = http().post(format!("{RS_URL}/resource")).header("origin", EVIL).bearer_auth(&token).call();
    assert_eq!(actual.header("access-control-allow-origin"), None);
}

#[test]
fn r1_r4_r6_an_actual_request_from_the_client_app() {
    let token = access_token("foo", "alice");
    let reply = http().post(format!("{RS_URL}/resource")).header("origin", CLIENT_URL).bearer_auth(&token).call();
    reply.assert_status(200);
    assert_eq!(reply.header("access-control-allow-origin"), Some(CLIENT_URL));
    assert_eq!(reply.header("access-control-allow-credentials"), None);
    let vary = reply.header_all("vary").join(",").to_ascii_lowercase();
    assert!(vary.contains("origin"), "Vary was {vary:?}");
}

#[test]
fn r7_scripts_can_read_why_they_were_refused() {
    let reply = http().post(format!("{RS_URL}/resource")).header("origin", CLIENT_URL).call();
    reply.assert_status(401);
    assert_eq!(reply.header("access-control-allow-origin"), Some(CLIENT_URL), "errors need CORS headers too");
    let exposed = lower(reply.header("access-control-expose-headers"));
    assert!(exposed.contains("www-authenticate"), "Access-Control-Expose-Headers was {exposed:?}");
}

#[test]
fn r1_never_a_wildcard() {
    for origin in [CLIENT_URL, EVIL, "null"] {
        let reply = preflight(origin, "GET");
        assert_ne!(reply.header("access-control-allow-origin"), Some("*"), "for Origin: {origin}");
    }
}
