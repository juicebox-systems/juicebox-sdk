use std::collections::HashMap;
use std::ffi::CStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use async_trait::async_trait;
use futures::channel::oneshot::{channel, Sender};
use libc::c_char;
use loam_sdk as sdk;

pub type AuthTokenGetFn = unsafe extern "C" fn(
    context: &AuthTokenManager,
    context_id: u64,
    realm_id: *const [u8; 16],
    callback: AuthTokenGetCallbackFn,
);
pub type AuthTokenGetCallbackFn = unsafe extern "C" fn(
    context: *mut AuthTokenManager,
    context_id: u64,
    auth_token: *const c_char,
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
    auth_token: *const c_char,
) {
    if context.is_null() {
        return;
    }

    let auth_token = if auth_token.is_null() {
        None
    } else {
        Some(sdk::AuthToken::from(
            unsafe { CStr::from_ptr(auth_token) }
                .to_str()
                .expect("invalid string for auth token")
                .to_owned(),
        ))
    };

    (*context).get_callback(context_id, auth_token);
}
