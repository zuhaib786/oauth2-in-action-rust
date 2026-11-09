# 13-1 · OpenID Connect

|                |                                                                                       |
|----------------|---------------------------------------------------------------------------------------|
| **Book**       | chapter 13, "User authentication with OAuth 2.0"                                      |
| **Specs**      | [OpenID Connect Core 1.0][core] §2, §3.1, §5.3 · [OpenID Connect Discovery 1.0][discovery] §3 |
| **You change** | `authorization-server` and `client`                                                   |
| **Tests**      | `cargo test -p acceptance --test ch13_ex1`                                            |

## Why

OAuth tells a client it may do things for a user. It doesn't tell the client
**who** the user is, and the obvious workaround is broken. "I got an access
token for the user's profile API, so whoever is in the profile is logged in"
works until someone shows up with an access token that was issued to a
*different* client. A malicious app the user once approved can replay its
token at your login and be the user. An access token was never addressed to
you.

**OpenID Connect** adds what's missing:

- An **ID token**: a signed JWT, issued with the tokens when the client asks
  for scope `openid`, whose `aud` is the client's own `client_id`. It says who
  logged in (`iss` + `sub`), for whom (`aud`), and when.
- A **nonce**: the client puts a random value in the authorization request,
  and the server copies it into the ID token. The client checks it, so an ID
  token can't be replayed into another login.
- A **UserInfo endpoint**: an OAuth-protected API on the authorization server
  that returns the user's profile claims, depending on the scopes (`profile`,
  `email`, ...).
- **Discovery**: a JSON document at `/.well-known/openid-configuration`
  listing the server's endpoints, keys and capabilities, so clients don't
  hard-code them.

## Requirements

### Authorization server

**R1.** `GET /.well-known/openid-configuration` ([Discovery §3][discovery-3])
returns at least: `issuer` (`http://localhost:9001/`, exactly the `iss` in
your tokens), `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`,
`jwks_uri`, `registration_endpoint`, `scopes_supported` (with `openid`),
`response_types_supported`, `subject_types_supported` (`["public"]`),
`id_token_signing_alg_values_supported` (`["RS256"]`) and
`code_challenge_methods_supported` (`["S256"]`).

**R2.** Add the scopes `openid`, `profile` and `email` (to `oauth-client-1`
and to what clients may register). When an authorization code was issued with
`openid` among its approved scopes, the token response also carries an
`id_token` ([Core §3.1.3.3][core-3.1.3.3]). It's signed with RS256 and your
key from 11-3, and its claims are:

| claim   | value                                                              |
|---------|--------------------------------------------------------------------|
| `iss`   | `http://localhost:9001/`                                           |
| `sub`   | the user's `sub`                                                   |
| `aud`   | the client's `client_id`                                           |
| `iat`, `exp` | now, and a few minutes later                                  |
| `nonce` | the `nonce` from the authorization request, if there was one       |

Give it the header `typ` `JWT`, not `at+jwt`. It is **not** an access token,
and the protected resource and `/userinfo` must refuse it.

**R3.** `/userinfo` ([Core §5.3][core-5.3]), GET and POST, takes an access
token in the `Authorization: Bearer` header. Only active access tokens, as
11-4's introspection judges them, with scope `openid`. It returns `sub`, plus
`name` and `preferred_username` with scope `profile`, plus `email` and
`email_verified` with scope `email`. No token → 401. A bad, revoked or non-access
token → 401 `invalid_token`. A good token without `openid` → 403
`insufficient_scope`.

### Client

**R4.** The web client logs the user in:

- It asks for `openid profile email` along with its other scopes (register
  them, too) and sends a fresh random `nonce`, kept in the session like `state`.
- On the callback, it validates the ID token ([Core §3.1.3.7][core-3.1.3.7]):
  signature from the server's JWKS, RS256 only, `iss` the server, `aud` its own
  `client_id`, not expired, `nonce` equal to the one it sent. Any failure → an
  error page and no login. (Not tested: the server signs correctly.)
- It fetches `/userinfo` and shows the user on its home page as the text
  `Logged in as <name>`, for example `Logged in as Alice`.

## Try it

```sh
curl -s http://localhost:9001/.well-known/openid-configuration | python3 -m json.tool
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:9001/userinfo
```

## Hints

- The nonce is just another parameter of the authorization request, which you
  already keep with each code.
- 11-4's `/introspect` already decides whether an access token is active.
  `/userinfo` needs the same decision without the audience check: pull it out
  of the handler.
- In the client, `jsonwebtoken::jwk::JwkSet`, `DecodingKey::from_jwk` and
  `Validation` do the ID token's signature and claims. The nonce check is yours.
- The ID token's `sub` and the UserInfo `sub` must match ([Core
  §5.3.2][core-5.3.2]). If they don't, don't use the UserInfo answer.

## Going further (not tested)

Make the client read the discovery document instead of hard-coding the
authorization server's URLs. Then add `at_hash` to the ID token ([Core
§3.1.3.6][core-3.1.3.6]), which binds it to the access token issued alongside.

[core]: https://openid.net/specs/openid-connect-core-1_0.html
[core-3.1.3.3]: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
[core-3.1.3.6]: https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
[core-3.1.3.7]: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
[core-5.3]: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
[core-5.3.2]: https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
[discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[discovery-3]: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
