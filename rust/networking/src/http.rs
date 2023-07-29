//! An HTTP [`Client`] trait, allowing integration
//! with the HTTP client of your choice.

use async_trait::async_trait;
use http::{status::InvalidStatusCode, StatusCode};
use std::collections::HashMap;

/// The [`Request`] Method (VERB).
#[derive(Debug)]
pub enum Method {
    Get,
    Put,
    Post,
    Delete,
}

impl Method {
    /// A string representation of the [`Method`].
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Delete => "DELETE",
        }
    }
}

/// A request which should be executed by your HTTP [`Client`].
#[derive(Debug)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

/// A response to a submitted [`Request`].
#[derive(Debug)]
pub struct Response {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    /// A [`http::StatusCode`](StatusCode) representation of the [`u8`] `status_code`.
    pub fn status(&self) -> Result<StatusCode, InvalidStatusCode> {
        StatusCode::from_u16(self.status_code)
    }
}

/// A trait representing an HTTP Client that can asynchronously
/// make requests and return responses. It should be implemented
/// using the `async_trait` crate.
#[async_trait]
pub trait Client: Sync {
    /// Called when the HTTP [`Client`] should perform a [`Request`]
    /// and return the [`Response`] or [`None`] if unable to
    /// perform the request.
    async fn send(&self, request: Request) -> Option<Response>;
}
