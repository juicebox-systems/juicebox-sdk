use async_trait::async_trait;
use futures::channel::oneshot::{channel, Sender};
use juicebox_sdk as sdk;
use libc::c_char;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem::take;
use std::sync::Mutex;
use uuid::Uuid;

use crate::array::{ManagedArray, UnmanagedArray};

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
    pub headers: UnmanagedArray<HttpHeader>,
    pub body: UnmanagedArray<u8>,
}

impl Drop for HttpRequest {
    fn drop(&mut self) {
        unsafe {
            if !self.url.is_null() {
                drop(CString::from_raw(self.url as *mut c_char));
            }

            if !self.headers.is_null() {
                let headers = take(&mut self.headers).to_managed();
                for header in headers.0.into_iter() {
                    if !header.name.is_null() {
                        drop(CString::from_raw(header.name as *mut c_char));
                    }

                    if !header.value.is_null() {
                        drop(CString::from_raw(header.value as *mut c_char));
                    }
                }
            }

            if !self.body.is_null() {
                drop(take(&mut self.body).to_managed());
            }
        }
    }
}

impl From<sdk::http::Request> for HttpRequest {
    fn from(request: sdk::http::Request) -> Self {
        let method = HttpRequestMethod::from(request.method);
        let url = CString::new(request.url.to_string()).unwrap().into_raw() as *const c_char;
        let body = match request.body {
            Some(body) => ManagedArray(body).to_unmanaged(),
            None => UnmanagedArray::null(),
        };
        let headers = ManagedArray::from(request.headers).to_unmanaged();
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

#[derive(Debug)]
#[repr(C)]
pub struct HttpResponse {
    pub id: [u8; 16],
    pub status_code: u16,
    pub headers: UnmanagedArray<HttpHeader>,
    pub body: UnmanagedArray<u8>,
}

impl From<&HttpResponse> for sdk::http::Response {
    fn from(ffi: &HttpResponse) -> Self {
        let body = ffi.body.to_vec();

        let headers = ffi
            .headers
            .as_slice()
            .iter()
            .filter_map(|header| {
                let name = unsafe { CStr::from_ptr(header.name) }
                    .to_str()
                    .ok()?
                    .to_owned();
                let value = unsafe { CStr::from_ptr(header.value) }
                    .to_str()
                    .ok()?
                    .to_owned();
                Some((name, value))
            })
            .collect::<HashMap<_, _>>();

        sdk::http::Response {
            status_code: ffi.status_code,
            headers,
            body,
        }
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

        {
            let request_ffi = HttpRequest::from(request);

            {
                let mut request_map = self.request_map.lock().unwrap();
                request_map.insert(request_ffi.id, tx);
            }

            unsafe {
                (self.ffi_send)(self, &request_ffi, ffi_http_receive);
            }
        }

        rx.await.unwrap()
    }
}

unsafe extern "C" fn ffi_http_receive(context: *mut HttpClient, response_ffi: *const HttpResponse) {
    if response_ffi.is_null() || context.is_null() {
        return;
    }

    let response = match sdk::http::Response::try_from(&*response_ffi) {
        Ok(response) => Some(response),
        Err(_) => None,
    };

    (*context).receive((*response_ffi).id, response);
}

#[derive(Debug)]
#[repr(C)]
pub struct HttpHeader {
    name: *const c_char,
    value: *const c_char,
}

impl From<HashMap<String, String>> for ManagedArray<HttpHeader> {
    fn from(value: HashMap<String, String>) -> Self {
        ManagedArray(
            value
                .into_iter()
                .map(|(name, value)| {
                    let name_cstr = CString::new(name).unwrap().into_raw();
                    let value_cstr = CString::new(value).unwrap().into_raw();
                    HttpHeader {
                        name: name_cstr,
                        value: value_cstr,
                    }
                })
                .collect(),
        )
    }
}
