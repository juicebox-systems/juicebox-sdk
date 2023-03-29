use loam_sdk_core::rpc::{Rpc, Service};
use loam_sdk_core::{marshalling, ClientError, HttpResponseStatus};
use std::collections::HashMap;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use url::Url;

#[derive(Debug)]
pub enum HttpMethod {
    Get,
    Put,
    Post,
    Delete,
}

#[derive(Debug)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub status: HttpResponseStatus,
    pub bytes: Vec<u8>,
}

pub trait HttpClient {
    fn send(&self, request: HttpRequest, callback: Box<dyn FnOnce(Option<HttpResponse>) + Send>);
}

pub async fn send_http<Http: HttpClient>(
    http: &Http,
    request: HttpRequest,
) -> Option<HttpResponse> {
    let (tx, rx) = futures::channel::oneshot::channel();

    http.send(
        request,
        Box::new(|res| {
            let _ = tx.send(res);
        }),
    );

    rx.await.unwrap()
}

pub async fn send_rpc<Http: HttpClient, R: Rpc<F>, F: Service>(
    http: &Http,
    base_url: Url,
    request: R,
) -> Result<R::Response, ClientError> {
    let url = base_url
        .join(R::PATH)
        .map_err(|_| ClientError::InvalidUrl)?;

    let mut headers = HashMap::new();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&Span::current().context(), &mut headers)
    });

    let body = match marshalling::to_vec(&request) {
        Ok(body) => body,
        Err(err) => return Err(ClientError::Serialization(err)),
    };

    match send_http(
        http,
        HttpRequest {
            method: HttpMethod::Post,
            url: url.to_string(),
            headers: headers,
            body: Some(body),
        },
    )
    .await
    {
        None => Err(ClientError::Network),
        Some(response) => {
            if response.status.is_success() {
                match marshalling::from_slice(&response.bytes) {
                    Ok(response) => Ok(response),
                    Err(err) => Err(ClientError::Deserialization(err)),
                }
            } else {
                Err(ClientError::HttpStatus(response.status))
            }
        }
    }
}
