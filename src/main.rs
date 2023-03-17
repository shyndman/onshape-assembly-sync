use std::time::SystemTime;

use base64::Engine as _;
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use http::header;
use mime::Mime;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use reqwest::blocking::RequestBuilder;
use reqwest::{IntoUrl, Method};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let client = OnShapeClient {
        http_client: reqwest::blocking::Client::new(),
        access_key: std::env::var("ONSHAPE_ACCESS_KEY")
            .expect("ONSHAPE_ACCESS_KEY must be set."),
        secret_key: std::env::var("ONSHAPE_SECRET_KEY")
            .expect("ONSHAPE_SECRET_KEY must be set."),
    };

    let builder = client.request(
        Method::GET,
        "https://cad.onshape.com/api/documents/85622754e9b97bcf5c74da64",
        mime::APPLICATION_JSON,
    );

    let response = builder.send().expect("Versions call must succeed");
    println!("response: {:#?}", response);
    println!("body: {}", response.text().expect("Success"));

    Ok(())
}

struct OnShapeClient {
    http_client: reqwest::blocking::Client,
    access_key: String,
    secret_key: String,
}

impl OnShapeClient {
    pub fn request<U: IntoUrl>(
        &self,
        method: Method,
        url: U,
        content_type: Mime,
    ) -> RequestBuilder {
        let url = url.into_url().expect("Could not convert to URL");

        // Prepare the signature
        let nonce = create_nonce();
        let date = httpdate::fmt_http_date(SystemTime::now());
        let path = url.path();
        let query: String = url.query().map_or("".into(), |val| {
            percent_encoding::percent_decode_str(val)
                .decode_utf8()
                .expect("Error parsing query")
                .into_owned()
        });

        let signature_plaintext =
            // NOTE: While not documented, the trailing newline is a requirement
            format!("{method}\n{nonce}\n{date}\n{content_type}\n{path}\n{query}\n")
                .to_lowercase();

        let mac = {
            let mut m = HmacSha256::new_from_slice(self.secret_key.as_bytes())
                .expect("HMAC can take key of any size");
            m.update(signature_plaintext.as_bytes());
            m
        };

        let authorization_val = format!(
            "On {access_key}:HmacSHA256:{signature}",
            access_key = self.access_key,
            // NOTE: The OnShape API requires that the signature be encoded as base64 with
            // padding characters, and as such, we use the STANDARD engine (not the
            // STANDARD_NO_PAD).
            signature =
                base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
        );

        self.http_client
            .request(method, url)
            .header(header::AUTHORIZATION, authorization_val)
            .header(
                header::ACCEPT,
                "application/vnd.onshape.v2+json;charset=UTF-8;qs=0.2",
            )
            .header(header::CONTENT_TYPE, content_type.to_string())
            .header(header::DATE, date)
            .header("On-Nonce", nonce)
    }
}

fn create_nonce() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(25)
        .map(char::from)
        .collect()
}
