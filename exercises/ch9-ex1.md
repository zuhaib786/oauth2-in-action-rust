# 9-1 · Authorization codes that can't be stolen and reused

|                |                                                                                   |
|----------------|-----------------------------------------------------------------------------------|
| **Book**       | chapter 9, "Redirect URI manipulation" and "Authorization code theft"             |
| **RFCs**       | [RFC 6749 §4.1.2][4.1.2], [§4.1.3][4.1.3], [§10.5][10.5], [§10.10][10.10]          |
| **You change** | `authorization-server/src/main.rs`                                                |
| **Tests**      | `cargo test -p acceptance --test ch9_ex1`                                         |

## Why

The authorization code is the one secret that passes through the browser in
the code grant, so it's the one everyone tries to steal. Four rules make a
stolen code much less useful.

1. **The redirect URI is checked twice.** Suppose the server's redirect URI
   matching is ever loose (a prefix match, a sloppy parser) and an attacker
   gets a code sent to a URI of their choosing. They still can't redeem it,
   because the token request has to repeat the **same** `redirect_uri` the
   code was issued for ([RFC 6749 §4.1.3][4.1.3]). This is the book's exercise.
2. **A code is good once, and briefly.** You did "once" in chapter 5. "Briefly"
   means minutes at most ([RFC 6749 §4.1.2][4.1.2] says 10 minutes maximum).
3. **A replayed code is evidence of theft.** If a code shows up a second time,
   either the client is buggy or someone else has a copy. Either way, the
   tokens the first use produced can't be trusted. The RFC says the server
   SHOULD revoke them, and here you will.
4. **Codes can't be guessed.** Chapter 5's codes are 8 alphanumeric
   characters: about 47 bits. [RFC 6749 §10.10][10.10] asks for a guessing
   probability of at most 2⁻¹²⁸.

Rule 3 means each token has to remember which code it came from. The
reference solution calls that a **grant**: one approval by one user for one
client, which every token issued from it points back to. Chapter 11 builds
revocation on top of the same idea.

## Requirements

**R1.** If the authorization request included a `redirect_uri`, the token
request MUST include the **same** value. Missing or different → 400
`invalid_grant`.

**R2.** A code expires **60 seconds** after it's issued. An expired code →
400 `invalid_grant`. (Not tested: the tests won't wait a minute.)

**R3.** A code presented a **second time** → 400 `invalid_grant`, and every
token that came from its first use stops working: the access and refresh tokens
it produced, and any access token obtained since with that refresh token. The
protected resource refuses those access tokens (401). The refresh token gets
`invalid_grant`. Tokens from other codes are unaffected.
(From 11-1 on, access tokens are self-contained, and the protected resource
can't hear about revocation until 11-4. So on `main` the R3 tests check only
the refresh tokens.)

**R4.** Authorization codes, and the `reqid` on the approval page, carry at
least 128 bits of randomness (22 or more characters, in the tests' terms).

**R5.** A code only works for the client it was issued to. Already true since
chapter 5, now tested.

## Try it

```sh
# 1. get a code from the client app's flow, but stop before /callback:
#    approve in the browser, then copy the code from the address bar
# 2. use it twice
curl -s -u oauth-client-1:oauth-client-secret-1 -d grant_type=authorization_code \
     -d code=$CODE -d redirect_uri=http://localhost:9000/callback http://localhost:9001/token
```

## Hints

- Where does a token record "which code it came from"? The database records
  are JSON, so any field you add is fine. The protected resource only looks at
  the fields it knows.
- Once a code has been used you still need to remember it. Otherwise you can't
  tell a replay from a made-up code.
- `Db::remove` takes a predicate, so it can drop every record of one grant at
  once.

[4.1.2]: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2
[4.1.3]: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
[10.5]: https://www.rfc-editor.org/rfc/rfc6749#section-10.5
[10.10]: https://www.rfc-editor.org/rfc/rfc6749#section-10.10
