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
    pub status: ResponseStatus,
    pub bytes: Vec<u8>,
}

#[derive(Copy, Clone, Debug)]
pub struct ResponseStatus {
    pub status: u16,
}

impl std::fmt::Display for ResponseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(code: {})", self.status)
    }
}

impl From<u16> for ResponseStatus {
    fn from(status: u16) -> Self {
        Self { status }
    }
}

impl ResponseStatus {
    pub fn response_type(self) -> ResponseStatusType {
        ResponseStatusType::from_status(self.status)
    }

    pub fn is_success(self) -> bool {
        self.response_type().is_success()
    }

    pub fn is_error(self) -> bool {
        self.response_type().is_error()
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ResponseStatusType {
    Unknown = 0,
    Informational = 100,
    Success = 200,
    Redirection = 300,
    ClientError = 400,
    ServerError = 500,
}

impl ResponseStatusType {
    pub fn from_status(status: u16) -> Self {
        match status {
            100..=199 => Self::Informational,
            200..=299 => Self::Success,
            300..=399 => Self::Redirection,
            400..=499 => Self::ClientError,
            500..=599 => Self::ServerError,
            _ => Self::Unknown,
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }

    pub fn is_error(self) -> bool {
        matches!(self, Self::ClientError | Self::ServerError)
    }
}

pub trait Client {
    fn send(&self, request: Request, callback: Box<dyn FnOnce(Option<Response>) + Send>);
}

pub async fn send<Http: Client>(http: &Http, request: Request) -> Option<Response> {
    let (tx, rx) = futures::channel::oneshot::channel();

    http.send(
        request,
        Box::new(|res| {
            let _ = tx.send(res);
        }),
    );

    rx.await.unwrap()
}
