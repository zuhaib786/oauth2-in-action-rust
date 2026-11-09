# 15-1 · DPoP: tokens bound to a key

|                |                                                                                       |
|----------------|---------------------------------------------------------------------------------------|
| **Book**       | chapter 15, "Beyond bearer tokens"                                                    |
| **RFCs**       | [RFC 9449][9449] (DPoP) §4, §5, §7 · [RFC 7638][7638] · [RFC 9700 §2.2][9700-2.2]      |
| **You change** | `authorization-server`, `protected-resource` and `native-client`                      |
| **Tests**      | `cargo test -p acceptance --test ch15_ex1`                                            |

## Why

Every token so far is a **bearer** token: whoever holds it can use it.
Tokens leak through logs, a compromised resource server, a malicious proxy,
browser storage. Rotation (11-5) and short lifetimes (11-1) limit the damage,
but the thief still gets a window.

A **sender-constrained** token is useless without a key that never leaves the
client. **DPoP** ([RFC 9449][9449], Demonstrating Proof of Possession) binds
tokens at the HTTP layer, so it works for browser and mobile apps that can't
do mutual TLS:

1. The client makes a key pair and keeps the private half.
2. With every request it sends a **DPoP proof** in a `DPoP` header: a small
   JWT signed with that key, with the public key in its header, the method
   (`htm`) and URL (`htu`) of this request, the time (`iat`), and a unique
   `jti`.
3. At the token endpoint, the server binds the token to the proof's key by
   putting the key's [RFC 7638][7638] thumbprint in the token as `cnf.jkt`,
   and answers `"token_type": "DPoP"`.
4. At the resource, the client sends `Authorization: DPoP <token>` and a fresh
   proof that also carries `ath`, the hash of the token. The resource checks
   the proof and that its key's thumbprint is the token's `cnf.jkt`.

A stolen token alone gets the thief nothing. A stolen proof is good for one
request, to one URL, for a minute.

## Requirements

### Checking a proof (RFC 9449 §4.3)

**R1.** A DPoP proof is valid only if:

- it's a JWT with `typ` `dpop+jwt` and `alg` `ES256`. ES256 is the only one
  you need to support, and nothing symmetric or `none` is acceptable.
- its header has a `jwk`, a public P-256 key with **no** private part (`d`),
  and the signature verifies with it
- `htm` is this request's method and `htu` this request's URL, without query
  or fragment
- `iat` is within 60 seconds of now, either way
- its `jti` hasn't been seen before. Remember the ones from the last couple of
  minutes; older ones fail the `iat` check anyway.
- at the resource: `ath` is the base64url SHA-256 of the access token

### Authorization server

**R2.** A token request with one valid `DPoP` header gets an access token with
`"cnf": {"jkt": "<thumbprint of the proof's key>"}` and `"token_type": "DPoP"`.
An invalid proof → 400 `invalid_dpop_proof`. No `DPoP` header → a bearer
token, as before.

A refresh token issued to a **public** client with a proof is bound to that
key too, because nothing else ties it to the client. Refreshing it needs a
proof from the **same** key, or → 400. Check the binding *before* the refresh
token is used up (11-5), or a thief's failed attempt burns the real client's
token. A **confidential** client's refresh tokens aren't bound: its client
authentication already constrains them, and it may move to a new key
([RFC 9449 §5][9449-5]). Either way, the new access token is bound to the key
that signed this request's proof.

Introspection (11-4) passes `cnf` through, so the resource can see it.

**R3.** The protected resource accepts `Authorization: DPoP <token>` with a
valid proof whose key's thumbprint equals the token's `cnf.jkt`. Otherwise →
401 with a `WWW-Authenticate: DPoP ...` challenge (`error="invalid_dpop_proof"`
or `"invalid_token"`, and `algs="ES256"`). A DPoP-bound token sent as
`Bearer` → 401 ([RFC 9449 §7.2][9449-7.2]). Bearer tokens still work as
`Bearer`.

### Native client

**R4.** `native-client` makes a fresh key pair on every run, sends proofs to
the token endpoint and the resource, and prints the token type it got as a
line `Token type: DPoP`.

## Try it

The proofs need a signature, so there's no curl one-liner this time. Run
`native-client` and watch the authorization server's log. Then take the token
it printed and try it with `Authorization: Bearer`.

## Hints

- `ring` 0.17 (already in the tree, under `jsonwebtoken`) makes P-256 keys:
  `EcdsaKeyPair::generate_pkcs8` with `ECDSA_P256_SHA256_FIXED_SIGNING`. The
  public key is 65 bytes: `0x04`, then `x`, then `y`. `sign` gives the 64-byte
  signature a JWS wants, so a proof is just
  `base64url(header).base64url(claims).base64url(signature)`.
- To check a proof, `jsonwebtoken` has `DecodingKey::from_ec_components(x, y)`.
  Its `Header` type quietly drops a `d` from the `jwk`, so look for private
  parts in the raw header JSON.
- The AS and the resource check proofs the same way. Where does that code live?
- The thumbprint is SHA-256 over `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`,
  exactly those members, in that order, no spaces.
- The resource rebuilds `htu` from its own base URL and the request's path.
  Don't trust a `Host` header for it.

## Going further (not tested)

[RFC 9449 §8](https://www.rfc-editor.org/rfc/rfc9449#section-8) adds server
nonces, so a client can't make proofs ahead of time. §10 binds the
authorization code itself to the key (`dpop_jkt`). And `/userinfo` (13-1) is a
protected resource too: teach it DPoP. [RFC 8705][8705] is the
mutual-TLS way to do the same job.

[9449]: https://www.rfc-editor.org/rfc/rfc9449
[9449-5]: https://www.rfc-editor.org/rfc/rfc9449#section-5
[9449-7.2]: https://www.rfc-editor.org/rfc/rfc9449#section-7.2
[7638]: https://www.rfc-editor.org/rfc/rfc7638
[8705]: https://www.rfc-editor.org/rfc/rfc8705
[9700-2.2]: https://www.rfc-editor.org/rfc/rfc9700#section-2.2
