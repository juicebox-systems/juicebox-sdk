use async_trait::async_trait;
use http::{status::InvalidStatusCode, StatusCode};
use std::collections::HashMap;

#[derive(Debug)]
pub enum Method {
    Get,
    Put,
    Post,
    Delete,
}

#[derive(Debug)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct Response {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> Result<StatusCode, InvalidStatusCode> {
        StatusCode::from_u16(self.status_code)
    }
}

#[async_trait]
pub trait Client: Sync {
    async fn send(&self, request: Request) -> Option<Response>;
}
