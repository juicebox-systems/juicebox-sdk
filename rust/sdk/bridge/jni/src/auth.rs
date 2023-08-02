use async_trait::async_trait;
use futures::channel::oneshot::{channel, Sender};
use jni::{
    objects::{GlobalRef, JByteArray, JValueGen},
    sys::jlong,
    JavaVM,
};
use juicebox_sdk as sdk;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

use crate::{
    jni_array, jni_object, jni_signature,
    types::{JNI_BYTE_TYPE, JNI_LONG_TYPE, JNI_VOID_TYPE, JUICEBOX_JNI_REALM_ID_TYPE},
};

pub struct AuthTokenManager {
    get_function: GlobalRef,
    jvm: JavaVM,
    await_get_map: Mutex<HashMap<i64, Sender<Option<sdk::AuthToken>>>>,
    next_await_id: AtomicI64,
}

impl AuthTokenManager {
    pub fn new(get_function: GlobalRef, jvm: JavaVM) -> Self {
        AuthTokenManager {
            get_function,
            jvm,
            await_get_map: Mutex::new(HashMap::new()),
            next_await_id: AtomicI64::new(0),
        }
    }

    pub fn get_callback(&self, context_id: i64, auth_token: Option<sdk::AuthToken>) {
        if let Some(tx) = self.await_get_map.lock().unwrap().remove(&context_id) {
            _ = tx.send(auth_token);
        }
    }
}

#[async_trait]
impl sdk::AuthTokenManager for AuthTokenManager {
    async fn get(&self, realm: &sdk::RealmId) -> Option<sdk::AuthToken> {
        let (tx, rx) = channel();
        {
            let mut env = self.jvm.attach_current_thread().unwrap();

            let id = self.next_await_id.fetch_add(1, Ordering::SeqCst);

            {
                let mut await_get_map = self.await_get_map.lock().unwrap();
                await_get_map.insert(id, tx);
            }

            let jrealm_id_array: JByteArray = env.byte_array_from_slice(&realm.0).unwrap();

            let java_realm_id_class = env.find_class(JUICEBOX_JNI_REALM_ID_TYPE).unwrap();

            let jrealm_id = env
                .new_object(
                    &java_realm_id_class,
                    jni_signature!((jni_array!(JNI_BYTE_TYPE)) => JNI_VOID_TYPE),
                    &[JValueGen::Object(&jrealm_id_array)],
                )
                .unwrap();

            env.call_method(
                &self.get_function,
                "get",
                jni_signature!((JNI_LONG_TYPE, JNI_LONG_TYPE, jni_object!(JUICEBOX_JNI_REALM_ID_TYPE)) => JNI_VOID_TYPE),
                &[
                    (self as *const AuthTokenManager as jlong).into(),
                    id.into(),
                    JValueGen::Object(&jrealm_id),
                ],
            )
            .unwrap();
        }
        rx.await.unwrap()
    }
}
