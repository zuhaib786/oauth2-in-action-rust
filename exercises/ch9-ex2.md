# 9-2 · Not an open redirector

|                |                                                                                  |
|----------------|----------------------------------------------------------------------------------|
| **Book**       | chapter 9, "Authorization server as open redirector"                             |
| **RFCs**       | [RFC 9700 §4.11.2][4.11.2] · [RFC 6749 §3.1][3.1], [§3.2][3.2], §3.3              |
| **You change** | `authorization-server/src/main.rs`                                               |
| **Tests**      | `cargo test -p acceptance --test ch9_ex2`                                        |

## Why

An **open redirector** is a URL on a trusted site that sends the browser on to
anywhere. Phishers love them: a link that starts with
`https://login.yourbank.example/authorize?...` looks safe, and lands on their
page.

Your `/authorize` only ever redirects to registered URIs, so it looks safe. But
think about who registers those URIs. In chapter 12, anyone will be able to
register a client, with the attacker's site as its redirect URI. Then an
attacker can build an `/authorize` link with a scope their client isn't allowed,
and your server answers by redirecting straight to the attacker's page with
`error=invalid_scope`. The user never saw an approval page. Your trusted domain
just forwarded them to the phisher. [RFC 9700 §4.11.2][4.11.2] says an
authorization server MUST only redirect automatically to a URI it trusts.

This exercise makes `/authorize` show an error page for scope errors, instead
of redirecting. It also tightens two loose ends in how the server reads its
input:

- **Approve can grant more than was asked for.** The approval form lists the
  scopes the client requested, but `/approve` accepts any scope the client is
  *allowed*. Someone posting the form by hand can add `scope_delete=on`.
- **Repeated parameters.** `?client_id=a&client_id=b`: which one wins depends on
  the parser. If one piece of code reads the first value and another reads the
  last, an attacker can get two parts of the server to disagree about which
  client this is. RFC 6749 §3.1 and §3.2 say each parameter MUST NOT appear
  more than once.

## Requirements

**R1.** At `/authorize`, a scope the client may not have gets the error page,
status 400, **no redirect**. This replaces R6 of 6-1, for both
`response_type=code` and `response_type=token`.

**R2.** At `/approve`, every approved scope must be one the client **requested**
in this authorization request. Otherwise: error page, status 400, no redirect.
Approving fewer scopes than requested is fine, as before.

**R3.** Any parameter that appears more than once in an `/authorize` request:
error page, status 400, no redirect.

**R4.** Any parameter that appears more than once in a `/token` request body:
400 `invalid_request`.

## Try it

```sh
curl -si 'http://localhost:9001/authorize?response_type=code&client_id=oauth-client-1&redirect_uri=http://localhost:9000/callback&scope=nuclear-launch' | head -1
curl -si 'http://localhost:9001/authorize?response_type=code&client_id=oauth-client-1&client_id=oauth-client-implicit&redirect_uri=http://localhost:9000/callback' | head -1
```

## Hints

- `Query<HashMap<String, String>>` has already thrown the duplicates away by
  the time your handler runs. `Query<Vec<(String, String)>>` (and the same with
  `Form`) keeps every pair, so you can check them yourself.
- If both endpoints need the same check, write it once.

## Going further (not tested)

R1 is the book's fix, and it's blunt: it also stops *legitimate* clients from
getting a proper `invalid_scope` error. A finer rule would redirect errors only
to redirect URIs the server has reason to trust. What could "trust" mean for a
dynamically registered client? Look at how RFC 9700 §4.11.2 phrases it.

[4.11.2]: https://www.rfc-editor.org/rfc/rfc9700#section-4.11.2
[3.1]: https://www.rfc-editor.org/rfc/rfc6749#section-3.1
[3.2]: https://www.rfc-editor.org/rfc/rfc6749#section-3.2
