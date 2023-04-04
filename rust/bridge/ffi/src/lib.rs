pub mod buffer;
pub mod http;

use libc::{c_char, c_void};
use loam_sdk as sdk;
use std::{ffi::CStr, ptr, str::FromStr};
use tokio::runtime::Runtime;
use url::Url;

use crate::buffer::{ManagedBuffer, UnmanagedBuffer};
use crate::http::{HttpClient, HttpSendFn};

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Configuration {
    pub realms: UnmanagedBuffer<Realm>,
    pub register_threshold: u8,
    pub recover_threshold: u8,
}

impl From<Configuration> for sdk::Configuration {
    fn from(ffi: Configuration) -> Self {
        let ffi_realms: Vec<Realm> = match ffi.realms.to_vec() {
            Ok(value) => value,
            Err(_) => panic!("realms pointer is unexpectedly null."),
        };

        let realms = ffi_realms.into_iter().map(sdk::Realm::from).collect();

        sdk::Configuration {
            realms,
            register_threshold: ffi.register_threshold,
            recover_threshold: ffi.recover_threshold,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Realm {
    pub id: [u8; 16],
    pub address: *const c_char,
    pub public_key: UnmanagedBuffer<u8>,
}

impl From<Realm> for sdk::Realm {
    fn from(ffi: Realm) -> Self {
        if ffi.address.is_null() {
            panic!("address pointer unexpectedly null.");
        }

        let address_str = match unsafe { CStr::from_ptr(ffi.address) }.to_str() {
            Ok(value) => value,
            Err(_) => panic!("Invalid string for address"),
        };

        let address = match Url::from_str(address_str) {
            Ok(value) => value,
            Err(_) => panic!("Invalid url for address"),
        };

        let public_key = match ffi.public_key.to_vec() {
            Ok(value) => value,
            Err(_) => panic!("public_key pointer unexpectedly null."),
        };

        sdk::Realm {
            address,
            public_key,
            id: sdk::RealmId(ffi.id),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AuthToken {
    pub tenant: *const c_char,
    pub user: *const c_char,
    pub signature: UnmanagedBuffer<u8>,
}

impl From<AuthToken> for sdk::AuthToken {
    fn from(ffi: AuthToken) -> Self {
        if ffi.tenant.is_null() {
            panic!("tenant pointer unexpectedly null.");
        }

        let tenant = match unsafe { CStr::from_ptr(ffi.tenant) }.to_str() {
            Ok(value) => value,
            Err(_) => panic!("Invalid string for tenant"),
        }
        .to_string();

        if ffi.user.is_null() {
            panic!("user pointer unexpectedly null.");
        }

        let user = match unsafe { CStr::from_ptr(ffi.user) }.to_str() {
            Ok(value) => value,
            Err(_) => panic!("Invalid string for user"),
        }
        .to_string();

        let signature = match ffi.signature.to_vec() {
            Ok(value) => value,
            Err(_) => panic!("signature pointer unexpectedly null."),
        };

        sdk::AuthToken {
            tenant,
            user,
            signature,
        }
    }
}

/// Creates a new opaque `LoamClient` reference.
///
/// The configuration provided must include at least one realm.
///
/// The `auth_token` represents the authority to act as a particular user
/// and should be valid for the lifetime of the `LoamClient`.
///
/// The function pointer `http_send` will be called when the client wishes
/// to make a network request. The appropriate request should be executed
/// by you, and the the response provided to the response function pointer.
/// This send should be performed asynchronously. `http_send` should not
/// block on performing the request, and the response should be returned
/// to the `response` function pointer argument when the asynchronous work
/// has completed.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_create(
    configuration: Configuration,
    auth_token: AuthToken,
    http_send: HttpSendFn,
) -> *mut sdk::Client<HttpClient> {
    let configuration = sdk::Configuration::from(configuration);
    let auth_token = sdk::AuthToken::from(auth_token);
    let client = sdk::Client::new(configuration, auth_token, HttpClient::new(http_send));
    Box::into_raw(Box::new(client))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_destroy(client: *mut sdk::Client<HttpClient>) {
    if !client.is_null() {
        drop(Box::from_raw(client))
    }
}

#[repr(C)]
pub enum RegisterError {
    InvalidAuth = 0,
    NetworkError,
    ProtocolError,
    Unavailable,
}

impl From<sdk::RegisterError> for RegisterError {
    fn from(value: sdk::RegisterError) -> Self {
        match value {
            sdk::RegisterError::InvalidAuth => Self::InvalidAuth,
            sdk::RegisterError::NetworkError => Self::NetworkError,
            sdk::RegisterError::ProtocolError => Self::ProtocolError,
        }
    }
}

/// Stores a new PIN-protected secret.
///
/// If it's successful, this also deletes any prior secrets for this user.
///
/// # Warning
///
/// If the secrets vary in length (such as passwords), the caller should
/// add padding to obscure the secrets' length.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_register(
    client: *mut sdk::Client<HttpClient>,
    context: *const c_void,
    pin: UnmanagedBuffer<u8>,
    secret: UnmanagedBuffer<u8>,
    num_guesses: u16,
    response: extern "C" fn(context: &c_void, error: *const RegisterError),
) {
    assert!(!client.is_null());
    let context = &*context;
    let pin = pin.to_vec().expect("pin pointer unexpectedly null");
    let secret = secret.to_vec().expect("secret pointer unexpectedly null");
    let client = &*client;

    Runtime::new().unwrap().spawn_blocking(move || {
        match Runtime::new().unwrap().block_on(async {
            client
                .register(
                    &sdk::Pin(pin),
                    &sdk::UserSecret(secret),
                    sdk::Policy { num_guesses },
                )
                .await
        }) {
            Ok(_) => (response)(context, ptr::null()),
            Err(err) => {
                let error_ptr = Box::into_raw(Box::new(RegisterError::from(err)));
                response(context, error_ptr);
                drop(Box::from_raw(error_ptr));
            }
        };
    });
}

#[repr(C)]
pub enum RecoverError {
    InvalidAuth = 0,
    NetworkError,
    Unsuccessful,
    ProtocolError,
}

impl From<sdk::RecoverError> for RecoverError {
    fn from(value: sdk::RecoverError) -> Self {
        match value {
            sdk::RecoverError::InvalidAuth => RecoverError::InvalidAuth,
            sdk::RecoverError::NetworkError => RecoverError::NetworkError,
            sdk::RecoverError::Unsuccessful(_) => RecoverError::Unsuccessful,
            sdk::RecoverError::ProtocolError => RecoverError::ProtocolError,
        }
    }
}

/// Retrieves a PIN-protected secret.
///
/// If it's successful, this also deletes any earlier secrets for this
/// user.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_recover(
    client: *mut sdk::Client<HttpClient>,
    context: *const c_void,
    pin: UnmanagedBuffer<u8>,
    response: extern "C" fn(
        context: &c_void,
        secret: UnmanagedBuffer<u8>,
        error: *const RecoverError,
    ),
) {
    assert!(!client.is_null());
    let context = &*context;
    let pin = pin.to_vec().expect("pin pointer unexpectedly null");
    let client = &*client;

    Runtime::new().unwrap().spawn_blocking(move || {
        match Runtime::new()
            .unwrap()
            .block_on(async { client.recover(&sdk::Pin(pin)).await })
        {
            Ok(secret) => {
                let secret = ManagedBuffer(secret.0).to_unmanaged();
                (response)(context, secret, ptr::null());
                drop(secret.to_managed());
            }
            Err(err) => {
                let error_ptr = Box::into_raw(Box::new(RecoverError::from(err)));
                (response)(context, UnmanagedBuffer::null(), error_ptr);
                drop(Box::from_raw(error_ptr));
            }
        };
    });
}

#[repr(C)]
pub enum DeleteError {
    InvalidAuth = 0,
    NetworkError,
    ProtocolError,
}

impl From<sdk::DeleteError> for DeleteError {
    fn from(value: sdk::DeleteError) -> Self {
        match value {
            sdk::DeleteError::InvalidAuth => DeleteError::InvalidAuth,
            sdk::DeleteError::NetworkError => DeleteError::NetworkError,
            sdk::DeleteError::ProtocolError => DeleteError::ProtocolError,
        }
    }
}

/// Deletes all secrets for this user.
///
/// Note: This does not delete the user's audit log.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_delete_all(
    client: *mut sdk::Client<HttpClient>,
    context: *const c_void,
    response: extern "C" fn(context: &c_void, error: *const DeleteError),
) {
    assert!(!client.is_null());
    let context = &*context;
    let client = &*client;

    Runtime::new().unwrap().spawn_blocking(move || {
        match Runtime::new()
            .unwrap()
            .block_on(async { client.delete_all().await })
        {
            Ok(_) => (response)(context, ptr::null()),
            Err(err) => {
                let error_ptr = Box::into_raw(Box::new(DeleteError::from(err)));
                (response)(context, error_ptr);
                drop(Box::from_raw(error_ptr));
            }
        };
    });
}
