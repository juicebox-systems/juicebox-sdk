use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

use crate::{http, requests::ClientError};
use loam_sdk_core::marshalling;

pub trait Service: Sync {}

pub trait Rpc<S: Service>: fmt::Debug + DeserializeOwned + Serialize {
    const PATH: &'static str;
    type Response: fmt::Debug + DeserializeOwned + Serialize;
}

pub async fn send<Http: http::Client, R: Rpc<F>, F: Service>(
    http: &Http,
    base_url: &Url,
    request: R,
) -> Result<R::Response, ClientError> {
    let url = base_url
        .join(R::PATH)
        .map_err(|_| ClientError::InvalidUrl)?;

    let mut headers = HashMap::new();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&Span::current().context(), &mut headers)
    });

    let body = marshalling::to_vec(&request).map_err(ClientError::Serialization)?;

    match http
        .send(http::Request {
            method: http::Method::Post,
            url: url.to_string(),
            headers,
            body: Some(body),
        })
        .await
    {
        None => Err(ClientError::Network),
        Some(response) => {
            if response.status.is_success() {
                Ok(marshalling::from_slice(&response.bytes)
                    .map_err(ClientError::Deserialization)?)
            } else {
                Err(ClientError::HttpStatus(response.status))
            }
        }
    }
}
