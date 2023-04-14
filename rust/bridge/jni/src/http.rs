use async_trait::async_trait;
use futures::channel::oneshot::{channel, Sender};
use jni::{
    objects::{GlobalRef, JObject, JObjectArray, JValue},
    sys::jlong,
    JNIEnv, JavaVM,
};
use loam_sdk as sdk;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

use crate::{
    jni_array, jni_object, jni_signature,
    types::{
        JNI_BYTE_TYPE, JNI_LONG_TYPE, JNI_STRING_TYPE, JNI_VOID_TYPE, LOAM_JNI_HTTP_HEADER_TYPE,
        LOAM_JNI_HTTP_REQUEST_TYPE,
    },
};

pub struct HttpClient {
    send_function: GlobalRef,
    jvm: JavaVM,
    request_map: Mutex<HashMap<[u8; 16], Sender<Option<sdk::http::Response>>>>,
}

impl HttpClient {
    pub fn new(send_function: GlobalRef, jvm: JavaVM) -> Self {
        HttpClient {
            send_function,
            jvm,
            request_map: Mutex::new(HashMap::new()),
        }
    }

    pub fn receive(&self, response_id: [u8; 16], response: Option<sdk::http::Response>) {
        if let Some(tx) = self.request_map.lock().unwrap().remove(&response_id) {
            let _ = tx.send(response);
        }
    }
}

#[async_trait(?Send)]
impl sdk::http::Client for HttpClient {
    async fn send(&self, request: sdk::http::Request) -> Option<sdk::http::Response> {
        let (tx, rx) = channel();

        let mut env = self.jvm.attach_current_thread().unwrap();

        let java_request_class = env.find_class(LOAM_JNI_HTTP_REQUEST_TYPE).unwrap();
        let java_request = env
            .new_object(java_request_class, jni_signature!(() => JNI_VOID_TYPE), &[])
            .unwrap();

        let id = *Uuid::new_v4().as_bytes();

        {
            let mut request_map = self.request_map.lock().unwrap();
            request_map.insert(id, tx);
        }

        set_byte_array(&mut env, &java_request, "id", &id);

        let method = match request.method {
            sdk::http::Method::Get => "GET",
            sdk::http::Method::Delete => "DELETE",
            sdk::http::Method::Put => "PUT",
            sdk::http::Method::Post => "POST",
        };
        set_string(&mut env, &java_request, "method", method);

        set_string(&mut env, &java_request, "url", request.url.as_str());

        if let Some(body) = request.body {
            set_byte_array(&mut env, &java_request, "body", &body);
        }

        let java_header_class = env.find_class(LOAM_JNI_HTTP_HEADER_TYPE).unwrap();

        let mut headers_array: Option<JObjectArray> = None;

        for (index, (name, value)) in request.headers.iter().enumerate() {
            let java_header = env
                .new_object(&java_header_class, jni_signature!(() => JNI_VOID_TYPE), &[])
                .unwrap();

            set_string(&mut env, &java_header, "name", name);
            set_string(&mut env, &java_header, "value", value);

            match &headers_array {
                Some(array) => {
                    env.set_object_array_element(array, index.try_into().unwrap(), java_header)
                        .unwrap();
                }
                None => {
                    headers_array = Some(
                        env.new_object_array(
                            request.headers.len().try_into().unwrap(),
                            jni_object!(LOAM_JNI_HTTP_HEADER_TYPE),
                            java_header,
                        )
                        .unwrap(),
                    );
                }
            };
        }

        if let Some(array) = headers_array {
            env.set_field(
                &java_request,
                "headers",
                jni_array!(jni_object!(LOAM_JNI_HTTP_HEADER_TYPE)),
                JValue::Object(&array),
            )
            .unwrap();
        }

        env.call_method(
            &self.send_function,
            "send",
            jni_signature!((JNI_LONG_TYPE, jni_object!(LOAM_JNI_HTTP_REQUEST_TYPE)) => JNI_VOID_TYPE),
            &[
                (self as *const HttpClient as jlong).into(),
                JValue::Object(&java_request),
            ],
        )
        .unwrap();

        rx.await.unwrap()
    }
}

fn set_string(env: &mut JNIEnv, obj: &JObject, name: &str, string: &str) {
    let java_string = env.new_string(string).unwrap();
    env.set_field(
        obj,
        name,
        jni_object!(JNI_STRING_TYPE),
        JValue::Object(&java_string),
    )
    .unwrap();
}

fn set_byte_array(env: &mut JNIEnv, obj: &JObject, name: &str, array: &[u8]) {
    let java_array = env.byte_array_from_slice(array).unwrap();
    env.set_field(
        obj,
        name,
        jni_array!(JNI_BYTE_TYPE),
        JValue::Object(&java_array),
    )
    .unwrap();
}
