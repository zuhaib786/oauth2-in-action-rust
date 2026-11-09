//! word-bot: adds words to the Words API with nobody logged in.
//!
//! It gets an access token for itself with the client credentials grant
//! (chapter 6) and uses that one token for every request.
//!
//! Run it with:  cargo run -p word-bot -- hello world

use std::process::ExitCode;

use oauth_common::encode_client_credentials;
use serde_json::Value;

const TOKEN_ENDPOINT: &str = "http://localhost:9001/token";
const WORDS_API: &str = "http://localhost:9002/words";

const CLIENT_ID: &str = "oauth-client-service";
const CLIENT_SECRET: &str = "oauth-client-secret-service";
const SCOPE: &str = "read write";

/// Any error, boxed. Good enough for a program that just reports and exits.
type Error = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> ExitCode {
    let words: Vec<String> = std::env::args().skip(1).collect();
    if words.is_empty() {
        eprintln!("usage: word-bot <word>...");
        return ExitCode::from(2);
    }

    match run(&words).await {
        Ok(all_words) => {
            println!("{all_words}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("word-bot: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Adds `words`, then returns all the words the Words API holds.
async fn run(words: &[String]) -> Result<String, Error> {
    let http = reqwest::Client::new();
    let token = get_token(&http).await?;

    for word in words {
        http.post(WORDS_API)
            .bearer_auth(&token)
            .form(&[("word", word)])
            .send()
            .await?
            .error_for_status()?;
        println!("added {word}");
    }

    let body: Value = http
        .get(WORDS_API)
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(body["words"].as_str().unwrap_or_default().to_string())
}

/// The client credentials grant: our own id and secret buy us a token.
async fn get_token(http: &reqwest::Client) -> Result<String, Error> {
    let res = http
        .post(TOKEN_ENDPOINT)
        .header("Authorization", format!("Basic {}", encode_client_credentials(CLIENT_ID, CLIENT_SECRET)))
        .form(&[("grant_type", "client_credentials"), ("scope", SCOPE)])
        .send()
        .await?;

    let status = res.status();
    let body: Value = res.json().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("the authorization server answered {status}: {}", body["error"]).into());
    }
    body["access_token"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| "the token response has no access_token".into())
}
