# 6-5 · A native app, with a loopback redirect

|                |                                                                           |
|----------------|---------------------------------------------------------------------------|
| **Book**       | chapter 6, "Native applications" (the book's 6-4, on assertions, has no code, so it's skipped) |
| **RFCs**       | [RFC 8252][8252] §4.1, §7.3, §8.3, §8.12                                  |
| **You change** | `authorization-server/src/main.rs`, and a new crate `native-client`       |
| **Tests**      | `cargo test -p acceptance --test ch6_ex5`                                 |

## Why

A native app (a desktop program, a phone app, a CLI like `gh auth login`) runs
on the user's machine. Like a browser app, it's a **public client**: anyone can
pull a secret out of the binary, so it doesn't get one. Unlike a browser app, it
can run a small web server of its own. That gives it the cleanest way to
receive the redirect: the **loopback redirect**.

1. The app starts listening on `127.0.0.1` on any free port.
2. It opens the system browser at the authorization endpoint with
   `redirect_uri=http://127.0.0.1:<port>/callback`.
3. The user logs in and approves in their own browser, with their saved
   passwords and their password manager. The app never sees their credentials
   ([RFC 8252 §8.12][8.12] says not to use an embedded web view).
4. The browser is redirected to the app's little server. The app takes the
   code, tells the browser it can close the tab, and trades the code for a token.

The port is only known when the app starts, so the authorization server can't
require an exact match. [RFC 8252 §7.3][7.3] says it MUST allow any port for
loopback redirect URIs.

There's a hole in this design that you leave open on purpose. Any other program
on the machine can also listen on loopback ports. If one of them catches the
code, it can trade it for a token, because a public client has no secret to
prove who it is. Chapter 10 (PKCE) closes that hole.

## Requirements

### Authorization server

**R1.** Register a fifth client:

| field           | value                                   |
|-----------------|-----------------------------------------|
| `client_id`     | `oauth-native-client`                   |
| `client_secret` | none: it's a public client              |
| `redirect_uris` | `http://127.0.0.1/callback`             |
| `scope`         | `foo bar`                               |
| `grant_types`   | `authorization_code`, `refresh_token`   |

**R2.** When a registered redirect URI is an `http` URI whose host is the
loopback IP literal `127.0.0.1` or `[::1]`, a requested redirect URI matches it
if **everything but the port** is the same: scheme, host, path, and no query or
fragment added. Every other redirect URI still needs an exact match.

**R3.** `localhost` doesn't count as loopback here. Its name can be resolved
to something else, and [RFC 8252 §8.3][8.3] says to use the IP literal.

**R4.** The native client trades its code at the token endpoint as a public
client: `client_id` in the form, no secret. If 6-1 is right, this works already.

### `native-client`

**R5.** A new binary crate `native-client` in this workspace.

**R6.** It listens on `127.0.0.1` on a port the operating system picks, and
uses `http://127.0.0.1:<port>/callback` as its redirect URI.

**R7.** It prints the authorization URL **on a line of its own** on stdout.
The URL asks for `response_type=code`, scope `foo bar` and a fresh, random
`state`. It may also open the URL in the system browser, but not when the
environment variable `NO_BROWSER` is set (the tests set it).

**R8.** It waits for the browser to come back to `/callback`. A wrong or
missing `state`, or an `error` from the authorization server, means: tell the
browser it failed, print why to stderr, exit with a non-zero status, and
**never** call the token endpoint. Requests for any other path get a 404 and
it keeps waiting. (Browsers ask for `/favicon.ico`.)

**R9.** On success, it answers the browser with a short HTML page saying it can
close the tab.

**R10.** It trades the code at the token endpoint as a public client, with the
same `redirect_uri`.

**R11.** It calls `POST /resource` with the access token, prints the JSON it
gets on stdout and exits with status 0.

**R12.** It gives up and exits non-zero if no callback arrives within 5
minutes. (Not tested.)

## Try it

```sh
cargo run -p native-client
```

Open the URL it prints, approve, and watch the terminal.

## Hints

- `tokio::net::TcpListener::bind("127.0.0.1:0")` gets you a free port, and
  `local_addr()` tells you which one.
- The tricky part is getting the code out of the request handler and back to
  your `main`. One way: a `tokio::sync::oneshot` channel, with its sender in
  the handler's state (wrapped in `Mutex<Option<...>>`, because a handler can
  run more than once but the sender can only be used once).
- Then the server has to stop, without cutting off the page it's still sending
  to the browser. Look at `axum::serve(...).with_graceful_shutdown(...)`.
- `tokio::time::timeout` needs tokio's `time` feature. Add it in this crate's
  `Cargo.toml`: `tokio = { workspace = true, features = ["time"] }`.
- To open a browser: `std::process::Command::new("open")` on macOS,
  `xdg-open` on Linux.

## Going further (not tested)

[RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) (the device authorization
grant) is how a TV or a CLI on a remote server logs in when there's no browser
on the same machine: it shows a short code, and you type it in on your phone.
Read §3 and work out which new endpoint the authorization server would need.

[8252]: https://www.rfc-editor.org/rfc/rfc8252
[7.3]: https://www.rfc-editor.org/rfc/rfc8252#section-7.3
[8.3]: https://www.rfc-editor.org/rfc/rfc8252#section-8.3
[8.12]: https://www.rfc-editor.org/rfc/rfc8252#section-8.12
