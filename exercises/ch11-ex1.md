# 11-1 · JWT access tokens

|                |                                                                                       |
|----------------|---------------------------------------------------------------------------------------|
| **Book**       | chapter 11, "Structured tokens: JSON Web Token (JWT)"                                 |
| **RFCs**       | [RFC 7519][7519] · [RFC 9068][9068] (JWT access tokens) · [RFC 7515 §2][7515-2]       |
| **You change** | `authorization-server` and `protected-resource`                                       |
| **Tests**      | `cargo test -p acceptance --test ch11_ex1`                                            |

## Why

So far an access token is a random string that means nothing by itself. The
protected resource looks it up in the authorization server's database, which
only works because both programs run on one machine and share
`database.jsonl`. Real deployments don't share a database. Either the resource
asks the server about every token (that's 11-4), or the token carries the
facts itself.

A **JSON Web Token** carries them. It's three base64url parts joined by dots:

```text
eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEvIi...
└──────────── header ─────────────────┘ └──────────── claims ──────────────────...  └ signature
```

The **header** says how the token is protected (`alg`) and what kind of token
it is (`typ`). The **claims** are a JSON object: who it's about (`sub`), who
issued it (`iss`), who it's for (`aud`), when it expires (`exp`), and so on.
The **signature** proves the authorization server wrote it.

In this exercise there is no signature: `"alg": "none"`. That lets you see
the structure without a crypto library, and it lets you see why nobody may
ever accept such a token. One of this exercise's tests mints a token out of
thin air and the protected resource believes it. 11-2 closes that hole.

Self-contained tokens have a price. The resource no longer asks anyone, so it
can't hear that a token was revoked. A token stays good until its `exp`, which
is why access tokens live minutes, not days. 9-1's code-replay tests now check
only the refresh tokens; 11-4 brings revocation back to access tokens.

## Requirements

### Authorization server

**R1.** Every access token the server issues is a JWT, from every grant:
authorization code, refresh token, client credentials, password, and
implicit. For now it is unsigned: `BASE64URL(header) "." BASE64URL(claims) "."`
with an empty third part. Base64url is the URL-safe alphabet **without**
`=` padding ([RFC 7515 §2][7515-2]). The header is
`{"alg":"none","typ":"at+jwt"}`.

**R2.** The claims ([RFC 9068 §2.2][9068-2.2]):

| claim       | value                                                                   |
|-------------|-------------------------------------------------------------------------|
| `iss`       | `"http://localhost:9001/"`                                              |
| `aud`       | `"http://localhost:9002/"`                                              |
| `sub`       | the user's `sub` (alice is `9XE3-JI34-00132A`), not their username. With no user (client credentials), the `client_id`. |
| `client_id` | the client the token was issued to                                      |
| `scope`     | the granted scopes, space-separated: `"foo bar"`                       |
| `iat`       | when it was issued, in whole seconds since 1970                        |
| `exp`       | `iat + 300`                                                             |
| `jti`       | a random id, unique for every token                                     |

**R3.** Refresh tokens stay random strings in the database. Keep saving a
record of each access token too, with its `jti` and grant. Nothing reads it in
this exercise, but 11-4 and 11-5 will. (Not tested.)

### Protected resource

**R4.** The resource stops reading the database. It decodes the token and
refuses it (401 with `error="invalid_token"`, never a 500) unless all of these
hold:

- three dot-separated parts, header and claims both base64url-encoded JSON objects
- `alg` is `none`, the only thing it can check for now, and the signature part is empty
- `typ` is `at+jwt` (or `application/at+jwt`, in any case). This stops other
  kinds of JWT being passed off as access tokens: chapter 13's ID tokens, for one.
- `iss` is exactly the authorization server's
- `aud` is ours, either the string itself or an array that contains it
  ([RFC 7519 §4.1.3][7519-aud])
- `exp` is present, a number, and not in the past
- `nbf` (not before), if present, is not in the future

You may allow up to 60 seconds of clock skew on `exp` and `nbf`.

**R5.** Scopes come from the `scope` claim. `/favorites` picks the user by
`sub`.

**R6.** The resource doesn't consult the database at all, so a token it has
never seen is accepted if its claims check out. Yes, that's a hole: the
`r6_anyone_can_mint_a_token` test mints one. 11-2 replaces that test with one
that expects the opposite.

## Try it

```sh
# copy an access token from the client app's page, then look inside:
python3 -c 'import sys,base64,json; p=sys.argv[1].split(".")[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p+"==")),indent=2))' "$TOKEN"

# and forge one: bob's favorites, no authorization server involved
b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }
H=$(printf '{"alg":"none","typ":"at+jwt"}' | b64url)
C=$(printf '{"iss":"http://localhost:9001/","aud":"http://localhost:9002/","sub":"1ZT5-OE63-57383B","scope":"read","exp":%d}' $(( $(date +%s) + 300 )) | b64url)
curl -s -H "Authorization: Bearer $H.$C." http://localhost:9002/favorites
```

## Hints

- No JWT library yet; that's 11-2. `base64`'s `URL_SAFE_NO_PAD` engine and
  `serde_json` are all you need.
- The token's claims replace the database record the resource used to get
  back. If the function that checks a token returns the claims, the handlers
  barely change.
- The authorization server knows users by username. `get_user` gets you
  their `sub`.
- `SystemTime::now().duration_since(UNIX_EPOCH)` gives you seconds since 1970.

## Going further (not tested)

[RFC 8725][8725], the JWT best current practices, lists the attacks on JWT
validation: `alg: none`, swapping algorithms, confusing one kind of token for
another. Read §2 now, and again after 11-3. Each attack is a rule you either
already follow or are about to.

[7519]: https://www.rfc-editor.org/rfc/rfc7519
[7519-aud]: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
[9068]: https://www.rfc-editor.org/rfc/rfc9068
[9068-2.2]: https://www.rfc-editor.org/rfc/rfc9068#section-2.2
[7515-2]: https://www.rfc-editor.org/rfc/rfc7515#section-2
[8725]: https://www.rfc-editor.org/rfc/rfc8725
