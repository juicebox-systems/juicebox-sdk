//! An [`http::Client`] implementation that utilizes [`reqwest`].

use ::http::{HeaderName, HeaderValue};
use async_trait::async_trait;
use reqwest::{Certificate, RequestBuilder};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;
use tracing::warn;

use crate::http;

/// Options for configuring the [`reqwest`] [`Client`].
#[derive(Debug, Clone)]
pub struct ClientOptions<'a> {
    pub additional_root_certs: Vec<Certificate>,
    pub timeout: Duration,
    pub default_headers: HashMap<&'a str, &'a str>,
}

impl<'a> Default for ClientOptions<'a> {
    fn default() -> Self {
        Self {
            additional_root_certs: Vec::new(),
            timeout: Duration::from_secs(30),
            default_headers: HashMap::from([(
                "User-Agent",
                concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")),
            )]),
        }
    }
}

/// An [`http::Client`] implementation that utilizes [`reqwest`].
#[derive(Clone, Debug, Default)]
pub struct Client {
    // reqwest::Client holds a connection pool. It's reference-counted
    // internally, so this field is relatively cheap to clone.
    http: reqwest::Client,
}

impl Client {
    pub fn new(options: ClientOptions) -> Self {
        let mut b = reqwest::Client::builder()
            .timeout(options.timeout)
            // The service checker needs access to the server's certificate to
            // warn if it will expire soon.
            .tls_info(true)
            .use_rustls_tls();

        let mut default_headers = reqwest::header::HeaderMap::new();
        for (key, value) in options.default_headers {
            if let (Ok(header_name), Ok(header_value)) =
                (HeaderName::from_str(key), HeaderValue::from_str(value))
            {
                default_headers.append(header_name, header_value);
            }
        }
        b = b.default_headers(default_headers);

        for c in options.additional_root_certs {
            b = b.add_root_certificate(c);
        }
        Self {
            http: b.build().expect("TODO"),
        }
    }

    pub fn to_reqwest(&self, request: http::Request) -> RequestBuilder {
        let mut request_builder = match request.method {
            http::Method::Get => self.http.get(request.url),
            http::Method::Put => self.http.put(request.url),
            http::Method::Post => self.http.post(request.url),
            http::Method::Delete => self.http.delete(request.url),
        };

        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in request.headers {
            if let (Ok(header_name), Ok(header_value)) =
                (HeaderName::from_str(&key), HeaderValue::from_str(&value))
            {
                headers.append(header_name, header_value);
            }
        }
        request_builder = request_builder.headers(headers);

        if let Some(body) = request.body {
            request_builder = request_builder.body(body);
        }

        if let Some(timeout) = request.timeout {
            request_builder = request_builder.timeout(timeout);
        }
        request_builder
    }

    pub async fn to_response(
        &self,
        resp: Result<reqwest::Response, reqwest::Error>,
    ) -> Result<http::Response, reqwest::Error> {
        match resp {
            Err(err) => {
                warn!(%err, "error sending HTTP request");
                Err(err)
            }
            Ok(response) => {
                let status = response.status().as_u16();
                let mut headers = HashMap::new();
                for (header_name, header_value) in response.headers() {
                    if let Ok(value) = header_value.to_str() {
                        headers.insert(header_name.to_string(), value.to_owned());
                    }
                }
                match response.bytes().await {
                    Err(err) => {
                        warn!(%err, "error receiving HTTP response");
                        Err(err)
                    }
                    Ok(bytes) => Ok(http::Response {
                        status_code: status,
                        headers,
                        body: bytes.to_vec(),
                    }),
                }
            }
        }
    }
}

#[async_trait]
impl http::Client for Client {
    async fn send(&self, request: http::Request) -> Option<http::Response> {
        let resp = self.to_reqwest(request).send().await;
        self.to_response(resp).await.ok()
    }
}
