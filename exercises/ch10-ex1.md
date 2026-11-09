# 10-1 · PKCE

|                |                                                                                     |
|----------------|-------------------------------------------------------------------------------------|
| **Book**       | chapter 10, "Proof Key for Code Exchange"                                           |
| **RFCs**       | [RFC 7636][7636] §4 · [RFC 9700 §2.1.1][2.1.1], [§4.8][4.8]                          |
| **You change** | `authorization-server`, `client` and `native-client`                                |
| **Tests**      | `cargo test -p acceptance --test ch10_ex1`                                          |

## Why

In 6-5 you left a hole open on purpose. A public client has no secret, so
whoever holds its authorization code can trade it for tokens: another app
listening on loopback, a malicious browser extension, anything that can read
the redirect.

**PKCE** ("pixie", Proof Key for Code Exchange) closes it with a one-time
secret that never travels through the browser:

1. Before each login, the client makes a random **code verifier** and keeps it.
2. It sends only a hash of it, the **code challenge**
   (`BASE64URL(SHA256(verifier))`), in the authorization request. The
   server stores the challenge with the code.
3. At the token endpoint, the client sends the verifier itself. The server
   hashes it and compares. Someone who stole the code never saw the verifier,
   and can't work it out from the challenge.

PKCE was invented for public clients. It also stops a different attack on
confidential ones, **code injection**: an attacker slips a stolen code into a
victim's own callback, so the victim's client redeems it and the attacker's
session ends up with the victim's tokens, or the other way around. That's why
[RFC 9700 §2.1.1][2.1.1] now asks every client to use it, and OAuth 2.1
requires it.

## Requirements

### Authorization server, `/authorize` (`response_type=code` only)

**R1.** Accept `code_challenge` and `code_challenge_method`. Support only
`S256`. Any other method, a challenge with no method (RFC 7636 says that
means `plain`), or a method with no challenge: redirect back with
`error=invalid_request`.

**R2.** A challenge must be exactly 43 characters of the base64url alphabet
(`A–Z a–z 0–9 - _`), which is what S256 always produces. Otherwise
`error=invalid_request`.

**R3.** **Public clients must use PKCE.** A `response_type=code` request from
a public client without a challenge: `error=invalid_request`. Confidential
clients may still leave it out.

### Authorization server, `/token`

**R4.** If the code was issued with a challenge, the token request must carry a
`code_verifier` whose S256 hash equals it. Missing or wrong → 400
`invalid_grant`.

**R5.** A verifier must be 43 to 128 characters from
`A–Z a–z 0–9 - . _ ~` ([RFC 7636 §4.1][4.1]). Otherwise → 400 `invalid_grant`.

**R6.** **Downgrade protection.** If the code was issued *without* a challenge,
a token request that carries a `code_verifier` → 400 `invalid_grant`
([RFC 9700 §4.8.2][4.8.2]). Otherwise an attacker who strips the challenge
out of the authorization request leaves PKCE switched off without either side
noticing.

### Clients

**R7.** The web client uses PKCE for every login: a fresh verifier per login,
kept in that browser's session (7-1), used once, with `S256`.

**R8.** `native-client` uses PKCE. It has to now, because of R3.

## Try it

```sh
VERIFIER=$(openssl rand -hex 40)
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
echo "http://localhost:9001/authorize?response_type=code&client_id=oauth-native-client&redirect_uri=http://127.0.0.1:5555/callback&scope=foo&state=x&code_challenge=$CHALLENGE&code_challenge_method=S256"
# open that, approve, copy the code from the (failed) page load, then:
curl -s -d client_id=oauth-native-client -d grant_type=authorization_code -d code=$CODE \
     -d redirect_uri=http://127.0.0.1:5555/callback -d code_verifier=$VERIFIER http://localhost:9001/token
```

## Hints

- `sha2` (version 0.10) for the hash and `base64`'s `URL_SAFE_NO_PAD` engine
  for the encoding. The AS, the client and native-client all need the same
  function. Where should it live?
- The verifier's alphabet is a superset of `random_string`'s, so
  `random_string(64)` is a fine verifier.
- In the authorization server, the challenge is already saved: it's in the
  `/authorize` request you keep with each code.

## Going further (not tested)

[RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) lets an authorization server
publish its metadata at `/.well-known/oauth-authorization-server`, including
`code_challenge_methods_supported`. Clients use that to know PKCE is supported
before they rely on it. Chapter 13 publishes the OpenID Connect version of this
document.

[7636]: https://www.rfc-editor.org/rfc/rfc7636#section-4
[4.1]: https://www.rfc-editor.org/rfc/rfc7636#section-4.1
[2.1.1]: https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1
[4.8]: https://www.rfc-editor.org/rfc/rfc9700#section-4.8
[4.8.2]: https://www.rfc-editor.org/rfc/rfc9700#section-4.8.2
