//! An [`http::Client`] implementation that utilizes [`reqwest`].

use ::http::{HeaderName, HeaderValue};
use async_trait::async_trait;
use reqwest::Certificate;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::str::FromStr;
use std::time::Duration;
use tracing::warn;

use crate::{http, rpc};

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
pub struct Client<F: rpc::Service> {
    // reqwest::Client holds a connection pool. It's reference-counted
    // internally, so this field is relatively cheap to clone.
    http: reqwest::Client,
    _phantom_data: PhantomData<F>,
}

impl<F: rpc::Service> Client<F> {
    pub fn new(options: ClientOptions) -> Self {
        let mut b = reqwest::Client::builder()
            .timeout(options.timeout)
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
            _phantom_data: PhantomData {},
        }
    }
}

#[async_trait]
impl<F: rpc::Service> http::Client for Client<F> {
    async fn send(&self, request: http::Request) -> Option<http::Response> {
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

        match request_builder.send().await {
            Err(err) => {
                warn!(%err, "error sending HTTP request");
                None
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
                        None
                    }
                    Ok(bytes) => Some(http::Response {
                        status_code: status,
                        headers,
                        body: bytes.to_vec(),
                    }),
                }
            }
        }
    }
}
