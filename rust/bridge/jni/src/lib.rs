pub mod auth;
pub mod http;

#[macro_use]
mod types;

use auth::AuthTokenManager;
use jni::{
    objects::{JByteArray, JClass, JLongArray, JObject, JObjectArray, JString, JThrowable, JValue},
    sys::{jboolean, jint, jlong, jshort},
    JNIEnv,
};
use juicebox_sdk as sdk;
use juicebox_sdk_bridge::{Client, DeleteError, RecoverError, RegisterError};
use std::collections::HashMap;
use std::str::FromStr;
use url::Url;

use crate::http::HttpClient;
use crate::types::{
    JNI_BYTE_TYPE, JNI_INTEGER_TYPE, JNI_SHORT_OBJECT_TYPE, JNI_SHORT_TYPE, JNI_STRING_TYPE,
    JNI_VOID_TYPE, JUICEBOX_JNI_HTTP_HEADER_TYPE, JUICEBOX_JNI_REALM_ID_TYPE,
};

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_clientCreate(
    mut env: JNIEnv,
    _class: JClass,
    configuration: jlong,
    previous_configurations: JLongArray,
    auth_token_get: JObject,
    http_send: JObject,
) -> jlong {
    let configuration = configuration as *mut sdk::Configuration;
    assert!(!configuration.is_null());

    let previous_configurations = env
        .get_array_elements(
            &previous_configurations,
            jni::objects::ReleaseMode::NoCopyBack,
        )
        .unwrap()
        .iter()
        .map(|configuration| {
            let configuration = *configuration as *mut sdk::Configuration;
            assert!(!configuration.is_null());
            (*configuration).to_owned()
        })
        .collect();

    let sdk = sdk::ClientBuilder::new()
        .configuration((*configuration).to_owned())
        .previous_configurations(previous_configurations)
        .auth_token_manager(AuthTokenManager::new(
            env.new_global_ref(auth_token_get).unwrap(),
            env.get_java_vm().unwrap(),
        ))
        .http(HttpClient::new(
            env.new_global_ref(http_send).unwrap(),
            env.get_java_vm().unwrap(),
        ))
        .tokio_sleeper()
        .build();

    Box::into_raw(Box::new(Client::new(sdk))) as jlong
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_clientDestroy(
    _env: JNIEnv,
    _class: JClass,
    client: jlong,
) {
    drop(Box::from_raw(
        client as *mut Client<HttpClient, AuthTokenManager>,
    ));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn Java_xyz_juicebox_sdk_internal_Native_configurationCreate(
    mut env: JNIEnv,
    _class: JClass,
    jrealms: JObjectArray,
    register_threshold: jint,
    recover_threshold: jint,
    pin_hashing_mode: JObject,
) -> jlong {
    let pin_hashing_mode: u8 = env
        .call_method(
            &pin_hashing_mode,
            "ordinal",
            jni_signature!(() => JNI_INTEGER_TYPE),
            &[],
        )
        .unwrap()
        .i()
        .unwrap()
        .try_into()
        .unwrap();

    let jrealms_length = env.get_array_length(&jrealms).unwrap();

    let mut realms = vec![];
    for index in 0..jrealms_length {
        let jrealm = env.get_object_array_element(&jrealms, index).unwrap();

        let java_id = env
            .get_field(&jrealm, "id", jni_object!(JUICEBOX_JNI_REALM_ID_TYPE))
            .unwrap()
            .l()
            .unwrap();
        let id = get_byte_array(&mut env, &java_id, "bytes").unwrap();

        let address_string = get_string(&mut env, &jrealm, "address");
        let address = Url::from_str(&address_string).unwrap();
        let public_key = get_byte_array(&mut env, &jrealm, "publicKey");

        realms.push(sdk::Realm {
            id: sdk::RealmId(id.try_into().unwrap()),
            address,
            public_key,
        });
    }

    Box::into_raw(Box::new(sdk::Configuration {
        realms,
        register_threshold: register_threshold.try_into().unwrap(),
        recover_threshold: recover_threshold.try_into().unwrap(),
        pin_hashing_mode: sdk::PinHashingMode::from(pin_hashing_mode),
    })) as jlong
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn Java_xyz_juicebox_sdk_internal_Native_configurationCreateFromJson(
    mut env: JNIEnv,
    _class: JClass,
    json: JString,
) -> jlong {
    let json: String = env.get_string(&json).unwrap().into();
    Box::into_raw(Box::new(sdk::Configuration::from_json(&json).unwrap())) as jlong
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_configurationDestroy(
    _env: JNIEnv,
    _class: JClass,
    configuration: jlong,
) {
    drop(Box::from_raw(configuration as *mut sdk::Configuration));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_configurationsAreEqual(
    _env: JNIEnv,
    _class: JClass,
    configuration1: jlong,
    configuration2: jlong,
) -> jboolean {
    let configuration1 = configuration1 as *mut sdk::Configuration;
    let configuration2 = configuration2 as *mut sdk::Configuration;
    if configuration1.is_null() && configuration2.is_null() {
        return true as jboolean;
    }
    if configuration1.is_null() || configuration2.is_null() {
        return false as jboolean;
    }
    (*configuration1 == *configuration2) as jboolean
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_clientRegister(
    mut env: JNIEnv,
    _class: JClass,
    client: jlong,
    pin: JByteArray,
    secret: JByteArray,
    info: JByteArray,
    num_guesses: jshort,
) {
    let client = &*(client as *const Client<HttpClient, AuthTokenManager>);
    let pin = env.convert_byte_array(pin).unwrap();
    let secret = env.convert_byte_array(secret).unwrap();
    let info = env.convert_byte_array(info).unwrap();
    let num_guesses = num_guesses.try_into().unwrap();

    if let Err(err) = client.runtime.block_on(client.sdk.register(
        &sdk::Pin::from(pin),
        &sdk::UserSecret::from(secret),
        &sdk::UserInfo::from(info),
        sdk::Policy { num_guesses },
    )) {
        let error = RegisterError::from(err);
        throw(&mut env, error as i32, "Register");
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_clientRecover<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    client: jlong,
    pin: JByteArray<'local>,
    info: JByteArray<'local>,
) -> JByteArray<'local> {
    let client = &*(client as *const Client<HttpClient, AuthTokenManager>);
    let pin = env.convert_byte_array(pin).unwrap();
    let info = env.convert_byte_array(info).unwrap();

    match client.runtime.block_on(
        client
            .sdk
            .recover(&sdk::Pin::from(pin), &sdk::UserInfo::from(info)),
    ) {
        Ok(secret) => env.byte_array_from_slice(secret.expose_secret()).unwrap() as JByteArray,
        Err(err) => {
            let error = RecoverError::from(err);
            let java_error_type = "xyz/juicebox/sdk/RecoverError";
            let java_error_class = env.find_class(java_error_type).unwrap();
            let java_error_values: JObjectArray = env
                .call_static_method(
                    java_error_class,
                    "values",
                    jni_signature!(() => jni_array!(jni_object!(java_error_type))),
                    &[],
                )
                .unwrap()
                .l()
                .unwrap()
                .into();
            let java_error = env
                .get_object_array_element(&java_error_values, error.reason as i32)
                .unwrap();
            let java_exception_class = env.find_class("xyz/juicebox/sdk/RecoverException").unwrap();

            let guesses_remaining: JObject = if error.guesses_remaining.is_null() {
                JObject::null()
            } else {
                env.new_object(
                    JNI_SHORT_OBJECT_TYPE,
                    jni_signature!((JNI_SHORT_TYPE) => JNI_VOID_TYPE),
                    &[unsafe { *error.guesses_remaining as jshort }.into()],
                )
                .unwrap()
            };

            let java_exception: JThrowable = env
                .new_object(
                    java_exception_class,
                    jni_signature!((jni_object!(java_error_type), jni_object!(JNI_SHORT_OBJECT_TYPE)) => JNI_VOID_TYPE),
                    &[
                        JValue::Object(&java_error),
                        JValue::Object(&guesses_remaining),
                    ],
                )
                .unwrap()
                .into();
            env.throw(java_exception).unwrap();
            JByteArray::default()
        }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_clientDelete(
    mut env: JNIEnv,
    _class: JClass,
    client: jlong,
) {
    let client = &*(client as *const Client<HttpClient, AuthTokenManager>);

    if let Err(err) = client.runtime.block_on(client.sdk.delete()) {
        let error = DeleteError::from(err);
        throw(&mut env, error as i32, "Delete");
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_httpClientRequestComplete(
    mut env: JNIEnv,
    _class: JClass,
    http_client: jlong,
    response: JObject,
) {
    let http_client = http_client as *const HttpClient;

    let id = get_byte_array(&mut env, &response, "id").expect("id should not be null");
    let status_code = get_short(&mut env, &response, "statusCode");
    let body = get_byte_array(&mut env, &response, "body").expect("body should not be null");

    let java_headers: JObjectArray = env
        .get_field(
            &response,
            "headers",
            jni_array!(jni_object!(JUICEBOX_JNI_HTTP_HEADER_TYPE)),
        )
        .unwrap()
        .l()
        .unwrap()
        .into();

    let java_headers_length = env.get_array_length(&java_headers).unwrap();

    let mut headers = HashMap::new();

    for index in 0..java_headers_length {
        let java_header = env.get_object_array_element(&java_headers, index).unwrap();

        let name_string = get_string(&mut env, &java_header, "name");
        let value_string = get_string(&mut env, &java_header, "value");

        headers.insert(name_string, value_string);
    }

    let response = sdk::http::Response {
        status_code,
        headers,
        body,
    };

    (*http_client).receive(id.try_into().unwrap(), Some(response));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_xyz_juicebox_sdk_internal_Native_authTokenGetComplete(
    mut env: JNIEnv,
    _class: JClass,
    context: jlong,
    context_id: jlong,
    auth_token: JString,
) {
    let auth_token_manager = context as *const AuthTokenManager;

    let auth_token = if auth_token.is_null() {
        None
    } else {
        let string: String = env.get_string(&auth_token).unwrap().into();
        Some(sdk::AuthToken::from(string))
    };

    (*auth_token_manager).get_callback(context_id, auth_token);
}

fn get_string(env: &mut JNIEnv, obj: &JObject, name: &str) -> String {
    let jstring: JString = env
        .get_field(obj, name, jni_object!(JNI_STRING_TYPE))
        .unwrap()
        .l()
        .unwrap()
        .into();
    env.get_string(&jstring).unwrap().into()
}

fn get_byte_array(env: &mut JNIEnv, obj: &JObject, name: &str) -> Option<Vec<u8>> {
    let jobject = env
        .get_field(obj, name, jni_array!(JNI_BYTE_TYPE))
        .unwrap()
        .l()
        .unwrap();
    if jobject.is_null() {
        return None;
    }
    let jbytearray: JByteArray = jobject.into();
    Some(env.convert_byte_array(jbytearray).unwrap())
}

fn get_short(env: &mut JNIEnv, obj: &JObject, name: &str) -> u16 {
    env.get_field(obj, name, JNI_SHORT_TYPE)
        .unwrap()
        .s()
        .unwrap()
        .try_into()
        .unwrap()
}

fn throw(env: &mut JNIEnv, error_code: i32, name: &str) {
    let java_error_type = format!("xyz/juicebox/sdk/{}Error", name);
    let java_error_class = env.find_class(&java_error_type).unwrap();
    let java_error_values: JObjectArray = env
        .call_static_method(
            java_error_class,
            "values",
            jni_signature!(() => jni_array!(jni_object!(java_error_type))),
            &[],
        )
        .unwrap()
        .l()
        .unwrap()
        .into();
    let java_error = env
        .get_object_array_element(&java_error_values, error_code)
        .unwrap();
    let java_exception_class = env
        .find_class(format!("xyz/juicebox/sdk/{}Exception", name))
        .unwrap();
    let java_exception: JThrowable = env
        .new_object(
            java_exception_class,
            jni_signature!((jni_object!(java_error_type)) => JNI_VOID_TYPE),
            &[JValue::Object(&java_error)],
        )
        .unwrap()
        .into();
    env.throw(java_exception).unwrap();
}
