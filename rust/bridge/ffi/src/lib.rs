pub mod array;
pub mod http;

use libc::{c_char, c_void};
use loam_sdk as sdk;
use std::{ffi::CStr, ptr, str::FromStr};
use tokio::runtime::Runtime;
use url::Url;

use crate::array::{ManagedArray, UnmanagedArray};
use crate::http::{HttpClient, HttpSendFn};

pub struct Client {
    sdk: sdk::Client<HttpClient>,
    runtime: Runtime,
}

#[derive(Debug)]
#[repr(C)]
pub struct Configuration {
    pub realms: UnmanagedArray<Realm>,
    pub register_threshold: u8,
    pub recover_threshold: u8,
}

impl From<Configuration> for sdk::Configuration {
    fn from(ffi: Configuration) -> Self {
        let realms = ffi.realms.as_slice().iter().map(sdk::Realm::from).collect();

        sdk::Configuration {
            realms,
            register_threshold: ffi.register_threshold,
            recover_threshold: ffi.recover_threshold,
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct Realm {
    pub id: [u8; 16],
    pub address: *const c_char,
    pub public_key: UnmanagedArray<u8>,
}

impl From<&Realm> for sdk::Realm {
    fn from(ffi: &Realm) -> Self {
        assert!(!ffi.address.is_null());
        let address_str = unsafe { CStr::from_ptr(ffi.address) }
            .to_str()
            .expect("invalid string for address");
        let address = Url::from_str(address_str).expect("invalid URL for address");

        let public_key = ffi.public_key.to_vec();

        sdk::Realm {
            address,
            public_key,
            id: sdk::RealmId(ffi.id),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct AuthToken {
    pub tenant: *const c_char,
    pub user: *const c_char,
    pub signature: UnmanagedArray<u8>,
}

impl From<&AuthToken> for sdk::AuthToken {
    fn from(ffi: &AuthToken) -> Self {
        assert!(!ffi.tenant.is_null());
        let tenant = unsafe { CStr::from_ptr(ffi.tenant) }
            .to_str()
            .expect("invalid string for tenant")
            .to_owned();

        assert!(!ffi.user.is_null());
        let user = unsafe { CStr::from_ptr(ffi.user) }
            .to_str()
            .expect("invalid string for user")
            .to_owned();

        let signature = ffi.signature.to_vec();

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
/// has completed. The request parameter is only valid for the lifetime
/// of the `http_send` function and should not be accessed after returning
/// from the function.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_create(
    configuration: Configuration,
    auth_token: AuthToken,
    http_send: HttpSendFn,
) -> *mut Client {
    let configuration = sdk::Configuration::from(configuration);
    let auth_token = sdk::AuthToken::from(&auth_token);
    let client = sdk::Client::new(configuration, auth_token, HttpClient::new(http_send));
    Box::into_raw(Box::new(Client {
        sdk: client,
        runtime: Runtime::new().unwrap(),
    }))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_destroy(client: *mut Client) {
    assert!(!client.is_null());
    drop(Box::from_raw(client))
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
    client: *mut Client,
    context: *const c_void,
    pin: UnmanagedArray<u8>,
    secret: UnmanagedArray<u8>,
    num_guesses: u16,
    response: extern "C" fn(context: &c_void, error: *const RegisterError),
) {
    assert!(!client.is_null());
    let context = &*context;
    let pin = pin.to_vec();
    let secret = secret.to_vec();
    let client = &*client;

    client.runtime.spawn_blocking(move || {
        match client.runtime.block_on(client.sdk.register(
            &sdk::Pin(pin),
            &sdk::UserSecret(secret),
            sdk::Policy { num_guesses },
        )) {
            Ok(_) => (response)(context, ptr::null()),
            Err(err) => {
                let error = RegisterError::from(err);
                response(context, &error);
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
    client: *mut Client,
    context: *const c_void,
    pin: UnmanagedArray<u8>,
    response: extern "C" fn(
        context: &c_void,
        secret: UnmanagedArray<u8>,
        error: *const RecoverError,
    ),
) {
    assert!(!client.is_null());
    let context = &*context;
    let pin = pin.to_vec();
    let client = &*client;

    client.runtime.spawn_blocking(move || {
        match client.runtime.block_on(client.sdk.recover(&sdk::Pin(pin))) {
            Ok(secret) => {
                let mut secret = ManagedArray(secret.0);
                (response)(context, secret.unmanaged_borrow(), ptr::null());
            }
            Err(err) => {
                let error = RecoverError::from(err);
                (response)(context, UnmanagedArray::null(), &error);
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
    client: *mut Client,
    context: *const c_void,
    response: extern "C" fn(context: &c_void, error: *const DeleteError),
) {
    assert!(!client.is_null());
    let context = &*context;
    let client = &*client;

    client.runtime.spawn_blocking(move || {
        match client.runtime.block_on(client.sdk.delete_all()) {
            Ok(_) => (response)(context, ptr::null()),
            Err(err) => {
                let error = DeleteError::from(err);
                (response)(context, &error);
            }
        };
    });
}
