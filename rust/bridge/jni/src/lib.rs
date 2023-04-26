pub mod http;

#[macro_use]
mod types;

use jni::{
    objects::{JByteArray, JClass, JObject, JObjectArray, JString, JThrowable, JValue},
    sys::{jlong, jshort},
    JNIEnv,
};
use loam_sdk as sdk;
use loam_sdk_bridge::{Client, DeleteError, RecoverError, RegisterError, TokioSleeper};
use std::collections::HashMap;
use std::str::FromStr;
use url::Url;

use crate::http::HttpClient;
use crate::types::{
    JNI_BYTE_TYPE, JNI_INTEGER_TYPE, JNI_SHORT_OBJECT_TYPE, JNI_SHORT_TYPE, JNI_STRING_TYPE,
    JNI_VOID_TYPE, LOAM_JNI_HTTP_HEADER_TYPE, LOAM_JNI_PIN_HASHING_MODE_TYPE, LOAM_JNI_REALM_TYPE,
};

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn Java_me_loam_sdk_internal_Native_clientCreate(
    mut env: JNIEnv,
    _class: JClass,
    configuration: JObject,
    previous_configurations: JObjectArray,
    auth_token: JString,
    http_send: JObject,
) -> jlong {
    let configuration = get_configuration(&mut env, &configuration);

    let java_previous_configurations = previous_configurations;
    let java_previous_configurations_length =
        env.get_array_length(&java_previous_configurations).unwrap();

    let mut previous_configurations = vec![];
    for index in 0..java_previous_configurations_length {
        let java_configuration = env
            .get_object_array_element(&java_previous_configurations, index)
            .unwrap();
        previous_configurations.push(get_configuration(&mut env, &java_configuration));
    }

    let auth_token: String = env.get_string(&auth_token).unwrap().into();

    let sdk = sdk::Client::new(
        configuration,
        previous_configurations,
        sdk::AuthToken::from(auth_token),
        HttpClient::new(
            env.new_global_ref(http_send).unwrap(),
            env.get_java_vm().unwrap(),
        ),
        TokioSleeper,
    );

    Box::into_raw(Box::new(Client::new(sdk))) as jlong
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_me_loam_sdk_internal_Native_clientDestroy(
    _env: JNIEnv,
    _class: JClass,
    client: jlong,
) {
    drop(Box::from_raw(client as *mut Client<HttpClient>));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_me_loam_sdk_internal_Native_clientRegister(
    mut env: JNIEnv,
    _class: JClass,
    client: jlong,
    pin: JByteArray,
    secret: JByteArray,
    num_guesses: jshort,
) {
    let client = &*(client as *const Client<HttpClient>);
    let pin = env.convert_byte_array(pin).unwrap();
    let secret = env.convert_byte_array(secret).unwrap();
    let num_guesses = num_guesses.try_into().unwrap();

    if let Err(err) = client.runtime.block_on(client.sdk.register(
        &sdk::Pin::from(pin),
        &sdk::UserSecret::from(secret),
        sdk::Policy { num_guesses },
    )) {
        let error = RegisterError::from(err);
        throw(&mut env, error as i32, "Register");
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_me_loam_sdk_internal_Native_clientRecover<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass,
    client: jlong,
    pin: JByteArray<'local>,
) -> JByteArray<'local> {
    let client = &*(client as *const Client<HttpClient>);
    let pin = env.convert_byte_array(pin).unwrap();

    match client
        .runtime
        .block_on(client.sdk.recover(&sdk::Pin::from(pin)))
    {
        Ok(secret) => env.byte_array_from_slice(secret.expose_secret()).unwrap() as JByteArray,
        Err(err) => {
            let error = RecoverError::from(err);
            let java_error_type = "me/loam/sdk/RecoverError";
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
            let java_exception_class = env.find_class("me/loam/sdk/RecoverException").unwrap();

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
pub unsafe extern "C" fn Java_me_loam_sdk_internal_Native_clientDeleteAll(
    mut env: JNIEnv,
    _class: JClass,
    client: jlong,
) {
    let client = &*(client as *const Client<HttpClient>);

    if let Err(err) = client.runtime.block_on(client.sdk.delete_all()) {
        let error = DeleteError::from(err);
        throw(&mut env, error as i32, "Delete");
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn Java_me_loam_sdk_internal_Native_httpClientRequestComplete(
    mut env: JNIEnv,
    _class: JClass,
    http_client: jlong,
    response: JObject,
) {
    let http_client = http_client as *const HttpClient;

    let id = get_byte_array(&mut env, &response, "id");
    let status_code = get_short(&mut env, &response, "statusCode");
    let body = get_byte_array(&mut env, &response, "body");

    let java_headers: JObjectArray = env
        .get_field(
            &response,
            "headers",
            jni_array!(jni_object!(LOAM_JNI_HTTP_HEADER_TYPE)),
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

fn get_string(env: &mut JNIEnv, obj: &JObject, name: &str) -> String {
    let jstring: JString = env
        .get_field(obj, name, jni_object!(JNI_STRING_TYPE))
        .unwrap()
        .l()
        .unwrap()
        .into();
    env.get_string(&jstring).unwrap().into()
}

fn get_byte_array(env: &mut JNIEnv, obj: &JObject, name: &str) -> Vec<u8> {
    let jbytearray: JByteArray = env
        .get_field(obj, name, jni_array!(JNI_BYTE_TYPE))
        .unwrap()
        .l()
        .unwrap()
        .into();
    env.convert_byte_array(jbytearray).unwrap()
}

fn get_byte(env: &mut JNIEnv, obj: &JObject, name: &str) -> u8 {
    env.get_field(obj, name, JNI_BYTE_TYPE)
        .unwrap()
        .b()
        .unwrap()
        .try_into()
        .unwrap()
}

fn get_short(env: &mut JNIEnv, obj: &JObject, name: &str) -> u16 {
    env.get_field(obj, name, JNI_SHORT_TYPE)
        .unwrap()
        .s()
        .unwrap()
        .try_into()
        .unwrap()
}

fn get_configuration(env: &mut JNIEnv, obj: &JObject) -> sdk::Configuration {
    let register_threshold = get_byte(env, obj, "registerThreshold");
    let recover_threshold = get_byte(env, obj, "recoverThreshold");

    let java_pin_hashing_mode = env
        .get_field(
            obj,
            "pinHashingMode",
            jni_object!(LOAM_JNI_PIN_HASHING_MODE_TYPE),
        )
        .unwrap()
        .l()
        .unwrap();
    let pin_hashing_mode: u8 = env
        .call_method(
            &java_pin_hashing_mode,
            "ordinal",
            jni_signature!(() => JNI_INTEGER_TYPE),
            &[],
        )
        .unwrap()
        .i()
        .unwrap()
        .try_into()
        .unwrap();

    let jrealms: JObjectArray = env
        .get_field(obj, "realms", jni_array!(jni_object!(LOAM_JNI_REALM_TYPE)))
        .unwrap()
        .l()
        .unwrap()
        .into();
    let jrealms_length = env.get_array_length(&jrealms).unwrap();

    let mut realms = vec![];
    for index in 0..jrealms_length {
        let jrealm = env.get_object_array_element(&jrealms, index).unwrap();

        let id = get_byte_array(env, &jrealm, "id");
        let address_string = get_string(env, &jrealm, "address");
        let address = Url::from_str(&address_string).unwrap();
        let public_key = get_byte_array(env, &jrealm, "publicKey");

        realms.push(sdk::Realm {
            id: sdk::RealmId(id.try_into().unwrap()),
            address,
            public_key,
        });
    }

    sdk::Configuration {
        realms,
        register_threshold,
        recover_threshold,
        pin_hashing_mode: sdk::PinHashingMode::from(pin_hashing_mode),
    }
}

fn throw(env: &mut JNIEnv, error_code: i32, name: &str) {
    let java_error_type = format!("me/loam/sdk/{}Error", name);
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
        .find_class(format!("me/loam/sdk/{}Exception", name))
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
