use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use url::Url;

use crate::http;
use loam_sdk_core::marshalling;
use loam_sdk_core::requests::{ClientRequest, ClientResponse};

pub trait Service: Sync {}

pub trait Rpc<S: Service>: fmt::Debug + DeserializeOwned + Serialize {
    const PATH: &'static str;
    type Response: fmt::Debug + DeserializeOwned + Serialize;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RpcError {
    Network,
    HttpStatus(u16),
    Serialization(marshalling::SerializationError),
    Deserialization(marshalling::DeserializationError),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RpcError::*;
        match self {
            Network => {
                write!(f, "network error")
            }
            HttpStatus(e) => {
                write!(f, "non-OK HTTP status: {e}")
            }
            Serialization(e) => {
                write!(f, "serialization error: {e:?}")
            }
            Deserialization(e) => {
                write!(f, "deserialization error: {e:?}")
            }
        }
    }
}

impl From<marshalling::SerializationError> for RpcError {
    fn from(value: marshalling::SerializationError) -> Self {
        RpcError::Serialization(value)
    }
}

impl From<marshalling::DeserializationError> for RpcError {
    fn from(value: marshalling::DeserializationError) -> Self {
        RpcError::Deserialization(value)
    }
}

#[derive(Clone, Debug)]
pub struct LoadBalancerService();
impl Service for LoadBalancerService {}

impl Rpc<LoadBalancerService> for ClientRequest {
    const PATH: &'static str = "req";
    type Response = ClientResponse;
}

pub async fn send<Http: http::Client, R: Rpc<F>, F: Service>(
    http: &Http,
    base_url: &Url,
    request: R,
) -> Result<R::Response, RpcError> {
    let url = base_url.join(R::PATH).unwrap();
    let body = marshalling::to_vec(&request).map_err(RpcError::Serialization)?;

    #[allow(unused_mut)]
    let mut headers = HashMap::new();

    #[cfg(feature = "distributed-tracing")]
    {
        use tracing::Span;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(&Span::current().context(), &mut headers)
        });
    }

    match http
        .send(http::Request {
            method: http::Method::Post,
            url: url.to_string(),
            headers,
            body: Some(body),
        })
        .await
    {
        None => Err(RpcError::Network),
        Some(response) => {
            if response
                .status()
                .map_err(|_| RpcError::Network)?
                .is_success()
            {
                Ok(marshalling::from_slice(&response.body).map_err(RpcError::Deserialization)?)
            } else {
                Err(RpcError::HttpStatus(response.status_code))
            }
        }
    }
}
