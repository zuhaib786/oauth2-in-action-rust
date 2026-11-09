# 11-3 · Public-key signatures (RS256) and a JWK Set

|                |                                                                                       |
|----------------|---------------------------------------------------------------------------------------|
| **Book**       | chapter 11, "Cryptographic protection of tokens: JOSE", the RS256 exercise            |
| **RFCs**       | [RFC 7518 §3.3][7518-3.3] · [RFC 7517][7517] (JWK) · [RFC 8725 §2.1][8725-2.1], [§3.1][8725-3.1] · [RFC 7638][7638] |
| **You change** | `authorization-server` and `protected-resource`                                       |
| **Tests**      | `cargo test -p acceptance --test ch11_ex3`                                            |

## Why

With HS256, every protected resource that can check a token can also forge
one. **RS256** splits the key in two. The authorization server signs with
the **private** key and keeps it to itself. Anyone can check the signature
with the **public** key, and holding it doesn't let you sign anything.

The resource still needs the public key, and it should get it from the
authorization server rather than a copy in its own source. The server
publishes its public keys as a **JWK Set** ([RFC 7517][7517]): a JSON
document at a well-known URL, here `/jwks`. Each key has a `kid` (key id),
and every token's header names the `kid` it was signed with. When the server
rotates keys, it publishes the new key first, starts signing with it, and
drops the old one once the old tokens have expired. Resources keep up by
fetching the set again when they see a `kid` they don't know.

Public keys bring their own attack, **algorithm confusion** ([RFC 8725
§2.1][8725-2.1]). Suppose a resource reads `alg` from the header and passes
"the key" to a generic verify function. An attacker takes the public key
(it's public), uses it as an **HMAC secret**, signs a token with `HS256`, and
the resource checks the HMAC with the very bytes the attacker used. The fix is
the rule from 11-2: the resource decides the algorithm, not the token.

## What's already there

`authorization-server/keys/signing-key.pem` is a 2048-bit RSA private key
(PKCS#8 PEM) for you to sign with. A real server generates its keys, keeps
them out of the repository, and rotates them. This one is in a public
repository, so it protects nothing.

## Requirements

### Authorization server

**R1.** Sign every access token with **RS256** and `keys/signing-key.pem`. The
header is `{"alg":"RS256","typ":"at+jwt","kid":"<the key's kid>"}`. Pick the
`kid` yourself; the [RFC 7638][7638] thumbprint of the public key is the
standard choice.

**R2.** `GET /jwks` returns the JWK Set: `{"keys": [ ... ]}` with the public
key as a JWK: `kty` `"RSA"`, `kid`, `use` `"sig"`, `alg` `"RS256"`, and `n`
and `e` (base64url, big-endian, no leading zero bytes; [RFC 7518
§6.3.1][7518-6.3.1]). **Never** the private parts (`d`, `p`, `q`, `dp`,
`dq`, `qi`).

### Protected resource

**R3.** Check signatures with the authorization server's published keys:

- Fetch the JWK Set from `http://localhost:9001/jwks`. Don't copy the key into
  the resource's source.
- Pick the key by the token's `kid`. No `kid`, or one the set doesn't have
  even after fetching it again → 401 `invalid_token`.
- Fetch the set when you first need it, keep it, and fetch again when you meet
  an unknown `kid`, but at most once every 10 seconds. Otherwise anyone can
  make you hammer the authorization server by sending made-up `kid`s. (Not
  tested.)
- Accept **only RS256**. HS256 with any secret, including the old shared one
  and the public key itself, → 401.

**R4.** All of 11-1's claim checks stay.

**R5.** The resource still doesn't consult the database. So a token stays good
until it expires, even after the authorization server has revoked its grant
(9-1's code replay, say). `r5_a_revoked_token_still_works` shows it. That's
the problem 11-4 solves, and it replaces that test.

## Try it

```sh
curl -s http://localhost:9001/jwks | python3 -m json.tool

# what the RFC 7638 thumbprint is made of: the required members, sorted, no spaces
python3 - <<'EOF'
import json, hashlib, base64, urllib.request
key = json.load(urllib.request.urlopen("http://localhost:9001/jwks"))["keys"][0]
canonical = json.dumps({k: key[k] for k in ("e", "kty", "n")}, separators=(",", ":"))
print(base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode())
EOF
```

## Hints

- Signing: `jsonwebtoken::EncodingKey::from_rsa_pem`. Set `Header::kid`.
- `n` and `e` have to come out of the PEM somehow. Two honest ways:
  - once, by hand, with `openssl rsa -in keys/signing-key.pem -noout -modulus`
    (`e` is 65537, which is `AQAB` in base64url), saved in a JSON file the
    server serves;
  - at startup, with the `rsa` crate (`RsaPrivateKey::from_pkcs8_pem`, then
    `.n()` and `.e()`).
- On the resource side, `jsonwebtoken::jwk::JwkSet` deserializes the set,
  `JwkSet::find` looks up a `kid`, and `DecodingKey::from_jwk` turns a JWK
  into a key.
- The resource now needs an HTTP client. `reqwest` is already in the
  workspace.
- The extractor gets the app state (`from_request(req, state)`). That's where
  the cached keys live.

## Going further (not tested)

Rotate the key. Generate a second one, publish both, sign with the new one,
and check that the resource picks it up without a restart.
[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) metadata (chapter 13's
`/.well-known/openid-configuration`) is how a resource finds `jwks_uri`
without hard-coding it.

[7517]: https://www.rfc-editor.org/rfc/rfc7517
[7518-3.3]: https://www.rfc-editor.org/rfc/rfc7518#section-3.3
[7518-6.3.1]: https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1
[7638]: https://www.rfc-editor.org/rfc/rfc7638
[8725-2.1]: https://www.rfc-editor.org/rfc/rfc8725#section-2.1
[8725-3.1]: https://www.rfc-editor.org/rfc/rfc8725#section-3.1
