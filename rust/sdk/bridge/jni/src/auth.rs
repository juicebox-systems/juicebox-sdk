use async_trait::async_trait;
use futures::channel::oneshot::{channel, Sender};
use jni::{
    objects::{GlobalRef, JByteArray, JClass, JString, JValueGen},
    sys::jlong,
    JNIEnv, JavaVM,
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

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_authTokenGetComplete(
    _env: JNIEnv,
    _class: JClass,
    context: jlong,
    context_id: jlong,
    auth_token: jlong,
) {
    let auth_token_manager = context as *const AuthTokenManager;
    let auth_token = auth_token as *const sdk::AuthToken;

    let auth_token = if auth_token.is_null() {
        None
    } else {
        Some((*auth_token).to_owned())
    };

    (*auth_token_manager).get_callback(context_id, auth_token);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn Java_xyz_juicebox_sdk_internal_Native_authTokenGeneratorCreateFromJson(
    mut env: JNIEnv,
    _class: JClass,
    json: JString,
) -> jlong {
    let json: String = env.get_string(&json).unwrap().into();
    Box::into_raw(Box::new(
        sdk::client_auth::AuthTokenGenerator::from_json(&json).unwrap(),
    )) as jlong
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_authTokenGeneratorDestroy(
    _env: JNIEnv,
    _class: JClass,
    generator: jlong,
) {
    drop(Box::from_raw(
        generator as *mut sdk::client_auth::AuthTokenGenerator,
    ));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_authTokenGeneratorVend(
    env: JNIEnv,
    _class: JClass,
    generator: jlong,
    realm_id: JByteArray,
    secret_id: JByteArray,
) -> jlong {
    let generator = generator as *mut sdk::client_auth::AuthTokenGenerator;
    let realm_id =
        TryInto::<[u8; 16]>::try_into(env.convert_byte_array(realm_id).unwrap()).unwrap();
    let secret_id =
        TryInto::<[u8; 16]>::try_into(env.convert_byte_array(secret_id).unwrap()).unwrap();
    Box::into_raw(Box::new((*generator).vend(
        &sdk::RealmId(realm_id),
        &sdk::client_auth::SecretId(secret_id),
    ))) as jlong
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn Java_xyz_juicebox_sdk_internal_Native_authTokenCreate(
    mut env: JNIEnv,
    _class: JClass,
    jwt: JString,
) -> jlong {
    let jwt: String = env.get_string(&jwt).unwrap().into();
    Box::into_raw(Box::new(sdk::AuthToken::from(jwt))) as jlong
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_authTokenDestroy(
    _env: JNIEnv,
    _class: JClass,
    token: jlong,
) {
    drop(Box::from_raw(token as *mut sdk::AuthToken));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_authTokenString<'a>(
    env: JNIEnv<'a>,
    _class: JClass<'a>,
    token: jlong,
) -> JString<'a> {
    let token = token as *mut sdk::AuthToken;
    env.new_string((*token).expose_secret()).unwrap()
}
