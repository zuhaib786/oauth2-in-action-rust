<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo-light.svg" alt="OAuth 2 in Action, Rust edition" width="520">
  </picture>
</p>

# OAuth 2 in Action — Rust edition

The exercises from [*OAuth 2 in Action*](https://github.com/oauthinaction/oauth-in-action-code)
(Justin Richer & Antonio Sanso, Apache 2.0), rebuilt in Rust as **one project
that grows chapter by chapter**.

The book gives every exercise its own separate copy of the code. Here there is
just one client, one protected resource and one authorization server. Each
exercise adds its feature to the same code, so by the end you have a single
authorization server with everything the book teaches.

## Getting the code

```sh
git clone https://github.com/zuhaib786/oauth2-in-action-rust.git
cd oauth2-in-action-rust
git tag        # the exercise tags come with the clone
```

You need Rust 1.85 or newer (install it from [rustup.rs](https://rustup.rs)).

## Running it

Open **three terminals** in this folder and run one program in each:

```sh
cargo run -p authorization-server   # http://localhost:9001
cargo run -p protected-resource     # http://localhost:9002
cargo run -p client                 # http://localhost:9000  ← open this in your browser
```

The first build downloads and compiles dependencies (about 20 s). After that,
builds are fast. Stop a program with Ctrl-C, and restart it after you change its code.

## Doing the exercises

Every exercise is two git tags:

- `chX-exY-start` is where you begin.
- `chX-exY-done` is the reference solution.

The `main` branch is the latest finished code. Chapters 3–5 and chapters 6
onwards work a little differently.

### Chapters 3–5: fill in the TODOs

At `chX-exY-start`, the exercise's parts of the code are replaced by `TODO` comments.

```sh
# 1. Start an exercise on your own branch
git switch -c my-ch3-ex1 ch3-ex1-start

# 2. Find the TODOs, write your code, run it, try it in the browser
grep -rn TODO client/src authorization-server/src protected-resource/src

# 3. Compare your work with the solution
git diff ch3-ex1-done

# 4. Save your work, then move on to the next exercise
git commit -am "my solution to 3-1"
git switch -c my-ch3-ex2 ch3-ex2-start
```

Each exercise starts from the official solution of the one before. If your
version came out different, that's fine: your branch still has it.

| Book exercise | Tag prefix | What you write | File | Browse |
|---|---|---|---|---|
| 3-1 | `ch3-ex1` | Client: get a token with the authorization code grant, use it | `client/src/main.rs` | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch3-ex1-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch3-ex1-start...ch3-ex1-done) |
| 3-2 | `ch3-ex2` | Client: use a refresh token when the access token stops working | `client/src/main.rs` | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch3-ex2-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch3-ex2-start...ch3-ex2-done) |
| 4-1 | `ch4-ex1` | Protected resource: find and check the incoming token | `protected-resource/src/main.rs` | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch4-ex1-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch4-ex1-start...ch4-ex1-done) |
| 4-2 | `ch4-ex2` | Protected resource: require `read`/`write`/`delete` scopes | `protected-resource/src/main.rs` | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch4-ex2-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch4-ex2-start...ch4-ex2-done) |
| 4-3 | `ch4-ex3` | Protected resource: return different data depending on scope | `protected-resource/src/main.rs` | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch4-ex3-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch4-ex3-start...ch4-ex3-done) |
| 4-4 | `ch4-ex4` | Protected resource: return different data depending on the user | `protected-resource/src/main.rs` | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch4-ex4-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch4-ex4-start...ch4-ex4-done) |
| 5-1 | `ch5-ex1` | Authorization server: `/authorize`, `/approve` and `/token` | `authorization-server/src/main.rs` | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch5-ex1-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch5-ex1-start...ch5-ex1-done) |
| 5-2 | `ch5-ex2` | Authorization server: issue and accept refresh tokens | `authorization-server/src/main.rs` | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch5-ex2-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch5-ex2-start...ch5-ex2-done) |
| 5-3 | `ch5-ex3` | Authorization server: scopes | `authorization-server/src/main.rs` | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch5-ex3-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch5-ex3-start...ch5-ex3-done) |

"solution" opens GitHub's diff view, so you see exactly what the exercise
changes and nothing else. Don't open it before you've tried!

### Chapter 6 onwards: a spec and tests, no skeleton

From chapter 6 there are no `TODO`s. Each exercise gives you two things:

- **`exercises/chX-exY.md`**, the spec: what to build, as numbered
  requirements, with the RFC sections they come from.
- **`acceptance/tests/chX_exY.rs`**, tests that check those requirements by
  talking to the running servers over HTTP, the way a browser or curl would.
  They only look at what your servers answer, so the code inside is entirely
  up to you: where it goes, what it's called, which crates you add.

```sh
git switch -c my-ch6-ex1 ch6-ex1-start
cat exercises/ch6-ex1.md

# write the code, (re)start the three servers, then:
cargo test -p acceptance --test ch6_ex1    # this exercise's tests
cargo test -p acceptance                   # everything so far, to check nothing broke

git diff ch6-ex1-done                      # compare with the reference solution
```

The tests need the servers running and fail with a clear message if they
aren't. Restart a server after you change its code: the tests talk to whatever
is running. The helpers they use are in `acceptance/src/lib.rs`, and you're
welcome to add tests of your own. Some requirements can't be checked from the
outside (how you store passwords, say). The spec marks those "not tested".

| Book exercise | Tag prefix | What you build | Spec | Browse |
|---|---|---|---|---|
| 6-1 | `ch6-ex1` | Authorization server: the implicit grant, public clients, grant types per client | [spec](exercises/ch6-ex1.md) | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch6-ex1-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch6-ex1-start...ch6-ex1-done) |
| 6-2 | `ch6-ex2` | Authorization server: the client credentials grant. A `word-bot` CLI that uses it | [spec](exercises/ch6-ex2.md) | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch6-ex2-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch6-ex2-start...ch6-ex2-done) |
| 6-3 | `ch6-ex3` | Authorization server: the password grant, password hashing, brute-force lockout | [spec](exercises/ch6-ex3.md) | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch6-ex3-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch6-ex3-start...ch6-ex3-done) |
| 6-5 | `ch6-ex5` | A `native-client` CLI with a loopback redirect. Authorization server: any port on loopback | [spec](exercises/ch6-ex5.md) | [start](https://github.com/zuhaib786/oauth2-in-action-rust/tree/ch6-ex5-start) · [solution](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch6-ex5-start...ch6-ex5-done) |

### One reader's solutions

The `solutions/zuhaib/*` branches hold the author's own attempts, written while
working through the exercises. Each one starts from the exercise's `start` tag,
so its diff is just that answer. For example,
[this 3-1](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch3-ex1-start...solutions/zuhaib/ch3-ex1)
vs [the reference 3-1](https://github.com/zuhaib786/oauth2-in-action-rust/compare/ch3-ex1-start...ch3-ex1-done).
Some of them use let chains (`if let ... && let ...`), which need Rust 1.88.

## Layout

```
client/                 the OAuth client (port 9000)
authorization-server/   the OAuth authorization server (port 9001)
protected-resource/     the protected API (port 9002)
  src/main.rs           the code
  templates/*.html      the web pages (from the book, using Jinja syntax)
common/                 small helpers shared by all three (see below)
acceptance/             black-box tests that run against the three servers
exercises/              the specs for chapter 6 onwards
database.jsonl          tokens issued by the authorization server and read by the
                        protected resource (created when the server starts)
```

## Reading the book's JavaScript as Rust

| Book (Node.js)                       | Rust                                           |
|--------------------------------------|------------------------------------------------|
| `node client.js`                     | `cargo run -p client`                          |
| `app.get('/x', function(req, res) {...})` | `async fn x(...) -> Response {...}` plus `.route("/x", get(x))` |
| `req.query.code`                     | `param(&query, "code")` (gives `""` if missing) or `query.get("code")` (an `Option`) |
| `req.body.code` (form POST)          | `Form(body)` in the arguments, then `param(&body, "code")` |
| `req.headers['authorization']`       | `headers.get("authorization")`                 |
| `res.render('index', {a: 1})`        | `render("index", context! { a => 1 })`         |
| `res.redirect(url)`                  | `Redirect::to(&url).into_response()`           |
| `res.status(401).json({...})`        | `(StatusCode::UNAUTHORIZED, Json(json!({...}))).into_response()` |
| `request('POST', url, {...})`        | `reqwest::Client::new().post(url)....send().await` |
| `randomstring.generate()`            | `random_string(32)`                            |
| `buildUrl(base, {...})`              | `build_url(base, &[("k", "v")])`               |
| `encodeClientCredentials(id, secret)`| `encode_client_credentials(id, secret)`        |
| global `var state = null`            | a field in the state struct, `Option<String>`, reached with `app.lock().await` |
| `nosql.insert({...})`                | `db.insert(json!({...}))`                      |
| `nosql.one()...where('x', v)`        | `db.find_one(\|doc\| doc["x"] == v)`           |
| `__.contains(list, x)`               | `list.contains(&x)` or `.iter().any(...)`      |
| `<%- x %>` in templates              | `{{ x }}`                                      |

## Rust things you'll bump into

- **`Option<T>`** is Rust's "value or null". You'll use `if let Some(x) = ...`
  or `let Some(x) = ... else { return ...; };` a lot.
- **`Result<T, E>`** is "value or error". HTTP calls return one, because the
  other server might be down.
- **`.await`** appears on anything that waits on the network. Every handler is an `async fn`.
- **`app.lock().await`** gives you access to the shared state. JS just uses
  globals for this. Rust needs a lock because many requests can run at once.
- **`String` vs `&str`**: `String` owns its text, and `&str` borrows someone else's.
  `.to_string()` or `String::from(...)` turns a `&str` into a `String`.
  `&my_string` or `.as_str()` goes the other way.
- The compiler's error messages are long but usually tell you exactly what to change. Read them.

## License

[Apache License 2.0](LICENSE), the same license as the book's code. This is a
port of the exercises from
[oauthinaction/oauth-in-action-code](https://github.com/oauthinaction/oauth-in-action-code)
by Justin Richer and Antonio Sanso. The HTML templates and the exercise
structure are adapted from that code. See [NOTICE](NOTICE).
