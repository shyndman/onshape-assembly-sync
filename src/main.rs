use std::time::SystemTime;

use base64::engine::general_purpose;
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
        "https://cad.onshape.com/api/v5/versions",
        mime::APPLICATION_JSON,
    );
    let response = builder.send().expect("Versions call must succeed");
    println!("{:#?}", response);

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
            format!("{method}\n{nonce}\n{date}\n{content_type}\n{path}\n{query}")
                .to_lowercase();
        println!("signature_plaintext: {}", signature_plaintext);

        let mac = {
            let mut m = HmacSha256::new_from_slice(self.secret_key.as_bytes())
                .expect("HMAC can take key of any size");
            m.update(signature_plaintext.as_bytes());
            m
        };

        let authorization_val = format!(
            "{}:HmacSHA256:{}",
            self.access_key,
            general_purpose::STANDARD_NO_PAD.encode(mac.finalize().into_bytes())
        );
        println!("authorization_val: {}", authorization_val);

        self.http_client
            .request(method, url)
            // .header(header::AUTHORIZATION, authorization_val)
            .header(header::ACCEPT, content_type.to_string())
            .header(header::DATE, date)
        // .header("On-Nonce", nonce)
    }
}

fn create_nonce() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(14)
        .map(char::from)
        .collect()
}
