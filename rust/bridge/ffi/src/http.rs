use crate::UnownedBuffer;
use futures::channel::oneshot::{channel, Sender};
use libc::c_char;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::Mutex;
use uuid::Uuid;

use async_trait::async_trait;
use loam_sdk as sdk;

#[derive(Debug)]
#[repr(C)]
pub enum HttpRequestMethod {
    Get = 0,
    Put,
    Post,
    Delete,
}

impl From<sdk::http::Method> for HttpRequestMethod {
    fn from(value: sdk::http::Method) -> Self {
        match value {
            sdk::http::Method::Get => Self::Get,
            sdk::http::Method::Delete => Self::Delete,
            sdk::http::Method::Post => Self::Post,
            sdk::http::Method::Put => Self::Put,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct HttpRequest {
    pub id: [u8; 16],
    pub method: HttpRequestMethod,
    pub url: *const c_char,
    pub headers: UnownedBuffer<HttpHeader>,
    pub body: UnownedBuffer<u8>,
}

impl Drop for HttpRequest {
    fn drop(&mut self) {
        unsafe {
            if !self.url.is_null() {
                drop(CString::from_raw(self.url as *mut c_char));
            }

            loam_http_headers_destroy(&self.headers);

            if !self.body.is_null() {
                drop(Box::from_raw(self.body.data as *mut u8));
            }
        }
    }
}

impl From<sdk::http::Request> for HttpRequest {
    fn from(request: sdk::http::Request) -> Self {
        let method = HttpRequestMethod::from(request.method);
        let url = CString::new(request.url.to_string()).unwrap().into_raw() as *const c_char;
        let body = match request.body {
            Some(body) => UnownedBuffer::from(body),
            None => UnownedBuffer::null(),
        };
        let headers = UnownedBuffer::from(request.headers);
        let id = *Uuid::new_v4().as_bytes();

        HttpRequest {
            id,
            method,
            url,
            headers,
            body,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HttpResponse {
    pub id: [u8; 16],
    pub status_code: u16,
    pub headers: UnownedBuffer<HttpHeader>,
    pub body: UnownedBuffer<u8>,
}

impl TryFrom<HttpResponse> for sdk::http::Response {
    type Error = &'static str;

    fn try_from(ffi: HttpResponse) -> Result<Self, Self::Error> {
        let body = match ffi.body.try_into() {
            Ok(value) => value,
            Err(_) => return Err("body pointer is unexpectedly null"),
        };

        if ffi.headers.is_null() {
            return Err("headers pointer is unexpectedly null.");
        }

        let headers_vec: Vec<HttpHeader> = match ffi.headers.try_into() {
            Ok(value) => value,
            Err(_) => return Err("headers pointer is unexpectedly null."),
        };

        let headers = headers_vec
            .into_iter()
            .fold(HashMap::new(), |mut acc, header| {
                let name = match unsafe { CStr::from_ptr(header.name) }.to_str() {
                    Ok(value) => value.to_string(),
                    Err(_) => return acc,
                };
                let value = match unsafe { CStr::from_ptr(header.value) }.to_str() {
                    Ok(value) => value.to_string(),
                    Err(_) => return acc,
                };
                acc.insert(name, value);
                acc
            });

        Ok(sdk::http::Response {
            status_code: ffi.status_code,
            headers,
            body,
        })
    }
}

pub type HttpSendFn = unsafe extern "C" fn(
    context: &HttpClient,
    request: *const HttpRequest,
    callback: HttpResponseFn,
);
pub type HttpResponseFn =
    unsafe extern "C" fn(context: *mut HttpClient, response: *const HttpResponse);

pub struct HttpClient {
    ffi_send: HttpSendFn,
    request_map: Mutex<HashMap<[u8; 16], Sender<Option<sdk::http::Response>>>>,
}

impl HttpClient {
    pub fn new(ffi_send: HttpSendFn) -> Self {
        HttpClient {
            ffi_send,
            request_map: Mutex::new(HashMap::new()),
        }
    }

    fn receive(&self, response_id: [u8; 16], response: Option<sdk::http::Response>) {
        if let Some(tx) = self.request_map.lock().unwrap().remove(&response_id) {
            let _ = tx.send(response);
        }
    }
}

#[async_trait]
impl sdk::http::Client for HttpClient {
    async fn send(&self, request: sdk::http::Request) -> Option<sdk::http::Response> {
        let (tx, rx) = channel();

        unsafe {
            let request_ffi = HttpRequest::from(request);
            let mut request_map = self.request_map.lock().unwrap();
            request_map.insert(request_ffi.id, tx);

            (self.ffi_send)(self, &request_ffi, ffi_http_receive);
        }

        rx.await.unwrap()
    }
}

unsafe extern "C" fn ffi_http_receive(context: *mut HttpClient, response_ffi: *const HttpResponse) {
    if response_ffi.is_null() || context.is_null() {
        return;
    }

    let response = match sdk::http::Response::try_from(*response_ffi) {
        Ok(response) => Some(response),
        Err(_) => None,
    };

    (*context).receive((*response_ffi).id, response);
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct HttpHeader {
    name: *const c_char,
    value: *const c_char,
}

impl From<HashMap<String, String>> for UnownedBuffer<HttpHeader> {
    fn from(value: HashMap<String, String>) -> Self {
        let mut headers = vec![];
        for (name, value) in value.iter() {
            let name_cstr = CString::new(name.clone()).unwrap().into_raw();
            let value_cstr = CString::new(value.clone()).unwrap().into_raw();
            headers.push(HttpHeader {
                name: name_cstr,
                value: value_cstr,
            });
        }

        UnownedBuffer::from(headers)
    }
}

unsafe extern "C" fn loam_http_headers_destroy(buffer: &UnownedBuffer<HttpHeader>) {
    if buffer.is_null() {
        return;
    }
    for i in 0..buffer.length {
        let header = buffer.data.add(i);
        if !header.is_null() {
            if !(*header).name.is_null() {
                drop(CString::from_raw((*header).name as *mut c_char));
            }

            if !(*header).value.is_null() {
                drop(CString::from_raw((*header).value as *mut c_char));
            }
        }
    }
}
