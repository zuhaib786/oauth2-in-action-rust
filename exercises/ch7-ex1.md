# 7-1 · Hardening the client

|                |                                                                                 |
|----------------|---------------------------------------------------------------------------------|
| **Book**       | chapter 7, "Common client vulnerabilities"                                      |
| **RFCs**       | [RFC 6749 §10.12][10.12] · [RFC 9700 §4.2][4.2], §4.7                           |
| **You change** | `client/src/main.rs`                                                            |
| **Tests**      | `cargo test -p acceptance --test ch7_ex1`                                       |

## Why

The web client from chapter 3 works, but only for one person at a time.
Everything it knows (the `state` it's waiting for, the tokens it holds) lives in
one global variable. That causes three problems:

1. **Everyone shares one login.** If Bob logs in, Alice's next click on "Get
   Protected Resource" shows Bob's data.
2. **`state` doesn't protect anyone.** It's supposed to tie the callback to
   the browser that started the login ([RFC 6749 §10.12][10.12]). With one
   global value, anyone's callback matches anyone's login. Worse, after a
   restart the client expects no state at all, and accepts a callback that has
   none. An attacker can then log you into *their* account by getting your
   browser to load `/callback?code=<their code>`. From then on, you save your
   data into their account.
3. **The code leaks.** The page shown at `/callback?code=...` loads Bootstrap
   from a CDN. Every one of those requests carries a `Referer` header with the
   full URL, code included ([RFC 9700 §4.2][4.2]). The code also stays in the
   address bar and in the history.

The book's own exercise here adds `state` to its native app. Yours already
checks state (6-5), so this exercise fixes the web client instead.

## Requirements

**R1.** The client gives each browser a **session cookie** named `session`: a
random value of at least 128 bits, with `HttpOnly`, `SameSite=Lax` and `Path=/`. It sets the
cookie on the browser's first visit to `/authorize`, at the latest. A cookie
value the client didn't hand out itself (from an old run, say) gets replaced
with a fresh one, not adopted.

**R2.** Everything the client keeps is **per session**: the pending `state`,
the access token, the scope and the refresh token. Two browsers never see each
other's tokens.

**R3.** `state` is **single-use**. The first callback consumes it, whether that
callback succeeds or fails.

**R4.** `/callback` is accepted only if its `state` equals the state of **this
session's** pending login. No session, no pending login, or no `state` in the
callback: refused.

**R5.** A refused callback answers with the error page and status **400**. It
**never** calls the token endpoint, and it leaves the session's tokens as they
were.

**R6.** A successful callback answers **`303 See Other` to `/`**, instead of
showing the page at the `/callback?code=...` URL.

**R7.** Every response from the client carries `Referrer-Policy: no-referrer`.

**R8.** An `error` in the callback (for example after the user clicks Deny)
also consumes the state, and shows the error page with status 400.

## Try it

Open the client in two different browsers (or one normal window and one
private window), log in as alice in one and bob in the other, and check that
Get Protected Resource and the Favorites API each show the right person.

```sh
# a callback out of nowhere: must be refused without calling the token endpoint
curl -si 'http://localhost:9000/callback?code=whatever' | head -1
```

## Hints

- Why `SameSite=Lax` and not `Strict`? The authorization server sends the
  browser back to `/callback` from another site. Work out what `Strict` would
  do to that request.
- Most handlers need "this browser's session". In axum, that's a job for
  either a custom extractor (`FromRequestParts`) or a middleware
  (`axum::middleware::from_fn_with_state`) that puts the session into the
  request's extensions and adds `Set-Cookie` to the response when it creates
  one. Think about which one can *add a header to the response*.
- Keep the lock you hold across `.await` as narrow as possible. One lock
  around all sessions, held while you call the token endpoint, makes every
  user wait for every other user.
- `axum::response::Redirect::to` already answers with 303.
- `tower_http::set_header::SetResponseHeaderLayer` adds a header to every
  response (tower-http's `set-header` feature).

## Going further (not tested)

- Sessions never expire and never go away. Add an idle timeout.
- The client trusts the authorization server's redirect blindly. Read about the
  "mix-up attack" in [RFC 9700 §4.4][4.4] and the `iss` response parameter
  ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)). When would this
  client need it?

[10.12]: https://www.rfc-editor.org/rfc/rfc6749#section-10.12
[4.2]: https://www.rfc-editor.org/rfc/rfc9700#section-4.2
[4.4]: https://www.rfc-editor.org/rfc/rfc9700#section-4.4
