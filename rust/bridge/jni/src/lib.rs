pub mod http;

use jni::{
    objects::{JByteArray, JClass, JObject, JObjectArray, JString, JThrowable, JValue},
    sys::{jlong, jshort},
    JNIEnv,
};
use loam_sdk as sdk;
use loam_sdk_bridge::{Client, DeleteError, RecoverError, RegisterError};
use std::collections::HashMap;
use std::str::FromStr;
use url::Url;

use crate::http::HttpClient;

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub extern "C" fn Java_me_loam_sdk_internal_Native_clientCreate(
    mut env: JNIEnv,
    _class: JClass,
    configuration: JObject,
    auth_token: JString,
    http_send: JObject,
) -> jlong {
    let auth_token: String = env.get_string(&auth_token).unwrap().into();
    let register_threshold = get_byte(&mut env, &configuration, "registerThreshold");
    let recover_threshold = get_byte(&mut env, &configuration, "recoverThreshold");

    let jrealms: JObjectArray = env
        .get_field(&configuration, "realms", "[Lme/loam/sdk/Realm;")
        .unwrap()
        .l()
        .unwrap()
        .into();
    let jrealms_length = env.get_array_length(&jrealms).unwrap();

    let mut realms = vec![];
    for index in 0..jrealms_length {
        let jrealm = env.get_object_array_element(&jrealms, index).unwrap();

        let id = get_byte_array(&mut env, &jrealm, "id");
        let address_string = get_string(&mut env, &jrealm, "address");
        let address = Url::from_str(&address_string).unwrap();
        let public_key = get_byte_array(&mut env, &jrealm, "publicKey");

        realms.push(sdk::Realm {
            id: sdk::RealmId(id.try_into().unwrap()),
            address,
            public_key,
        });
    }

    let sdk = sdk::Client::new(
        sdk::Configuration {
            realms,
            register_threshold,
            recover_threshold,
        },
        sdk::AuthToken::from(auth_token),
        HttpClient::new(
            env.new_global_ref(http_send).unwrap(),
            env.get_java_vm().unwrap(),
        ),
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
        &sdk::Pin(pin),
        &sdk::UserSecret(secret),
        sdk::Policy { num_guesses },
    )) {
        let error = RegisterError::from(err);
        let java_error_class = env.find_class("me/loam/sdk/RegisterError").unwrap();
        let java_error_values: JObjectArray = env
            .call_static_method(
                java_error_class,
                "values",
                "()[Lme/loam/sdk/RegisterError;",
                &[],
            )
            .unwrap()
            .l()
            .unwrap()
            .into();
        let java_error = env
            .get_object_array_element(&java_error_values, error as i32)
            .unwrap();
        let java_exception_class = env.find_class("me/loam/sdk/RegisterException").unwrap();
        let java_exception: JThrowable = env
            .new_object(
                java_exception_class,
                "(Lme/loam/sdk/RegisterError;)V",
                &[JValue::Object(&java_error)],
            )
            .unwrap()
            .into();
        env.throw(java_exception).unwrap();
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

    match client.runtime.block_on(client.sdk.recover(&sdk::Pin(pin))) {
        Ok(secret) => env.byte_array_from_slice(&secret.0).unwrap() as JByteArray,
        Err(err) => {
            let error = RecoverError::from(err);
            let java_error_class = env.find_class("me/loam/sdk/RecoverError").unwrap();
            let java_error_values: JObjectArray = env
                .call_static_method(
                    java_error_class,
                    "values",
                    "()[Lme/loam/sdk/RecoverError;",
                    &[],
                )
                .unwrap()
                .l()
                .unwrap()
                .into();
            let java_error = env
                .get_object_array_element(&java_error_values, error as i32)
                .unwrap();
            let java_exception_class = env.find_class("me/loam/sdk/RecoverException").unwrap();
            let java_exception: JThrowable = env
                .new_object(
                    java_exception_class,
                    "(Lme/loam/sdk/RecoverError;)V",
                    &[JValue::Object(&java_error)],
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
        let java_error_class = env.find_class("me/loam/sdk/DeleteError").unwrap();
        let java_error_values: JObjectArray = env
            .call_static_method(
                java_error_class,
                "values",
                "()[Lme/loam/sdk/DeleteError;",
                &[],
            )
            .unwrap()
            .l()
            .unwrap()
            .into();
        let java_error = env
            .get_object_array_element(&java_error_values, error as i32)
            .unwrap();
        let java_exception_class = env.find_class("me/loam/sdk/DeleteException").unwrap();
        let java_exception: JThrowable = env
            .new_object(
                java_exception_class,
                "(Lme/loam/sdk/DeleteError;)V",
                &[JValue::Object(&java_error)],
            )
            .unwrap()
            .into();
        env.throw(java_exception).unwrap();
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
            "[Lme/loam/sdk/internal/Native$HttpHeader;",
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
        .get_field(obj, name, "Ljava/lang/String;")
        .unwrap()
        .l()
        .unwrap()
        .into();
    env.get_string(&jstring).unwrap().into()
}

fn get_byte_array(env: &mut JNIEnv, obj: &JObject, name: &str) -> Vec<u8> {
    let jbytearray: JByteArray = env.get_field(obj, name, "[B").unwrap().l().unwrap().into();
    env.convert_byte_array(jbytearray).unwrap()
}

fn get_byte(env: &mut JNIEnv, obj: &JObject, name: &str) -> u8 {
    env.get_field(obj, name, "B")
        .unwrap()
        .b()
        .unwrap()
        .try_into()
        .unwrap()
}

fn get_short(env: &mut JNIEnv, obj: &JObject, name: &str) -> u16 {
    env.get_field(obj, name, "S")
        .unwrap()
        .s()
        .unwrap()
        .try_into()
        .unwrap()
}
