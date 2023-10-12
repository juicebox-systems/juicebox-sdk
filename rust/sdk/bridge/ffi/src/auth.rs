use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use futures::channel::oneshot::{channel, Sender};
use juicebox_sdk as sdk;
use libc::c_char;

#[derive(Debug)]
pub struct AuthTokenGenerator(sdk::AuthTokenGenerator);

#[derive(Debug)]
#[repr(C)]
pub struct AuthTokenParameters {
    pub realm_id: [u8; 16],
    pub user_id: [u8; 16],
}

#[derive(Debug)]
pub struct AuthToken(sdk::AuthToken);

pub type AuthTokenGetFn = unsafe extern "C" fn(
    context: &AuthTokenManager,
    context_id: u64,
    realm_id: *const [u8; 16],
    callback: AuthTokenGetCallbackFn,
);
pub type AuthTokenGetCallbackFn = unsafe extern "C" fn(
    context: *mut AuthTokenManager,
    context_id: u64,
    auth_token: *const AuthToken,
);

pub struct AuthTokenManager {
    ffi_get: AuthTokenGetFn,
    await_get_map: Mutex<HashMap<u64, Sender<Option<sdk::AuthToken>>>>,
    next_await_id: AtomicU64,
}

impl AuthTokenManager {
    pub fn new(ffi_get: AuthTokenGetFn) -> Self {
        AuthTokenManager {
            ffi_get,
            await_get_map: Mutex::new(HashMap::new()),
            next_await_id: AtomicU64::new(0),
        }
    }

    fn get_callback(&self, context_id: u64, auth_token: Option<sdk::AuthToken>) {
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
            let id = self.next_await_id.fetch_add(1, Ordering::SeqCst);

            {
                let mut await_get_map = self.await_get_map.lock().unwrap();
                await_get_map.insert(id, tx);
            }

            unsafe {
                (self.ffi_get)(self, id, &realm.0, ffi_get_callback);
            }
        }
        rx.await.unwrap()
    }
}

unsafe extern "C" fn ffi_get_callback(
    context: *mut AuthTokenManager,
    context_id: u64,
    auth_token: *const AuthToken,
) {
    if context.is_null() {
        return;
    }

    let auth_token = if auth_token.is_null() {
        None
    } else {
        Some((*auth_token).0.to_owned())
    };

    (*context).get_callback(context_id, auth_token);
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_auth_token_generator_create_from_json(
    json: *const c_char,
) -> *mut AuthTokenGenerator {
    assert!(!json.is_null());
    let json_str = unsafe { CStr::from_ptr(json) }
        .to_str()
        .expect("invalid json string");
    Box::into_raw(Box::new(AuthTokenGenerator(
        sdk::AuthTokenGenerator::from_json(json_str).expect("invalid generator json"),
    )))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_auth_token_generator_destroy(generator: *mut AuthTokenGenerator) {
    assert!(!generator.is_null());
    drop(Box::from_raw(generator));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_auth_token_generator_vend(
    generator: *mut AuthTokenGenerator,
    parameters: AuthTokenParameters,
) -> *const AuthToken {
    let generator = &*generator;
    Box::into_raw(Box::new(AuthToken(generator.0.vend(
        &sdk::RealmId(parameters.realm_id),
        &sdk::UserId(parameters.user_id),
    ))))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_auth_token_create(token_cstr: *const c_char) -> *const AuthToken {
    assert!(!token_cstr.is_null());
    let token_str = unsafe { CStr::from_ptr(token_cstr) }
        .to_str()
        .expect("invalid token_cstr string");
    Box::into_raw(Box::new(AuthToken(sdk::AuthToken::from(
        token_str.to_string(),
    ))))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_auth_token_destroy(token: *mut AuthToken) {
    assert!(!token.is_null());
    drop(Box::from_raw(token));
}
