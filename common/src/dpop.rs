//! DPoP (RFC 9449): checking the proofs a client sends to show it holds the
//! key its tokens are bound to. The authorization server checks them at the
//! token endpoint, and the protected resource with every request.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex, PoisonError},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The one signature algorithm we take proofs in. Goes in challenges and
/// metadata as `algs`.
pub const ALGORITHM: &str = "ES256";

/// How far a proof's `iat` may be from now, either way, in seconds.
const MAX_AGE: u64 = 60;

/// The `jti` of every proof accepted in the last [`MAX_AGE`] seconds, with
/// its `iat`. A proof is good for one request. Older ones can be forgotten:
/// they fail the `iat` check anyway.
static SEEN: LazyLock<Mutex<HashMap<String, u64>>> = LazyLock::new(Mutex::default);

/// Checks the proof in the `DPoP` header of a `method` request to `url`, if
/// there is one (RFC 9449 §4.3). At a resource, `access_token` is the token
/// it came with, whose hash the proof must carry. Returns the thumbprint of
/// the proof's key, which is what tokens are bound to, or `None` without a
/// proof.
pub fn check_request(
    headers: &HeaderMap,
    method: &str,
    url: &str,
    access_token: Option<&str>,
) -> Result<Option<String>, String> {
    let mut proofs = headers.get_all("dpop").iter();
    let proof = match (proofs.next(), proofs.next()) {
        (None, _) => return Ok(None),
        (Some(proof), None) => proof.to_str().map_err(|_| "the DPoP header isn't text")?,
        (Some(_), Some(_)) => return Err("more than one DPoP header".into()),
    };
    check_proof(proof, method, url, access_token).map(Some)
}

fn check_proof(proof: &str, method: &str, url: &str, access_token: Option<&str>) -> Result<String, String> {
    // jsonwebtoken checks the signature, but the header is ours to judge
    let header = raw_header(proof).ok_or("not a JWT")?;
    if header["typ"] != "dpop+jwt" {
        return Err("typ isn't dpop+jwt".into());
    }
    if header["alg"] != ALGORITHM {
        return Err(format!("alg isn't {ALGORITHM}"));
    }
    let jwk = &header["jwk"];
    if jwk.get("d").is_some() {
        return Err("the jwk has the private key in it".into());
    }
    let (Some(x), Some(y)) = (jwk["x"].as_str(), jwk["y"].as_str()) else {
        return Err("no P-256 public key in the header".into());
    };
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err("no P-256 public key in the header".into());
    }

    let key = DecodingKey::from_ec_components(x, y).map_err(|e| format!("a bad jwk: {e}"))?;
    let mut validation = Validation::new(Algorithm::ES256);
    // a proof has none of a token's claims
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<Value>(proof, &key, &validation)
        .map_err(|e| format!("the signature doesn't check out: {e}"))?
        .claims;

    if claims["htm"] != method {
        return Err(format!("made for a {} request", claims["htm"]));
    }
    if claims["htu"].as_str().map(without_query) != Some(without_query(url)) {
        return Err(format!("made for {}", claims["htu"]));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let iat = claims["iat"].as_u64().ok_or("no iat")?;
    if iat.abs_diff(now) > MAX_AGE {
        return Err("iat is too far from now".into());
    }
    if access_token.is_some_and(|token| claims["ath"] != URL_SAFE_NO_PAD.encode(Sha256::digest(token))) {
        return Err("ath isn't this token's hash".into());
    }
    let jti = claims["jti"].as_str().filter(|jti| !jti.is_empty()).ok_or("no jti")?;
    first_use(jti, iat, now)?;

    Ok(thumbprint(x, y))
}

/// The JSON of a JWT's header, unchecked.
fn raw_header(jwt: &str) -> Option<Value> {
    let header = URL_SAFE_NO_PAD.decode(jwt.split('.').next()?).ok()?;
    serde_json::from_slice(&header).ok()
}

/// `htu` is compared without the query and fragment.
fn without_query(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

/// Remembers a proof's `jti`, or fails if it's been seen before.
fn first_use(jti: &str, iat: u64, now: u64) -> Result<(), String> {
    let mut seen = SEEN.lock().unwrap_or_else(PoisonError::into_inner);
    seen.retain(|_, seen_iat| *seen_iat + MAX_AGE >= now);
    match seen.insert(jti.to_string(), iat) {
        Some(_) => Err("this proof was used before".into()),
        None => Ok(()),
    }
}

/// The RFC 7638 thumbprint of a P-256 key: the SHA-256 of its required
/// members, in this order, without spaces.
fn thumbprint(x: &str, y: &str) -> String {
    let members = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(members))
}
