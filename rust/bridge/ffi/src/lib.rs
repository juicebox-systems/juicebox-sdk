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

impl TryFrom<Configuration> for sdk::Configuration {
    type Error = &'static str;

    fn try_from(ffi: Configuration) -> Result<Self, Self::Error> {
        let ffi_realms: Vec<Realm> = match ffi.realms.to_vec() {
            Ok(value) => value,
            Err(_) => return Err("realms pointer is unexpectedly null."),
        };

        let mut realms = vec![];
        for ffi in ffi_realms.iter() {
            realms.push(match sdk::Realm::try_from(*ffi) {
                Ok(value) => value,
                Err(_) => return Err("Failed to parse realm"),
            })
        }

        Ok(sdk::Configuration {
            realms,
            register_threshold: ffi.register_threshold,
            recover_threshold: ffi.recover_threshold,
        })
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Realm {
    pub id: [u8; 16],
    pub address: *const c_char,
    pub public_key: UnmanagedBuffer<u8>,
}

impl TryFrom<Realm> for sdk::Realm {
    type Error = &'static str;

    fn try_from(ffi: Realm) -> Result<Self, Self::Error> {
        if ffi.address.is_null() {
            return Err("address pointer unexpectedly null.");
        }

        let address_str = match unsafe { CStr::from_ptr(ffi.address) }.to_str() {
            Ok(value) => value,
            Err(_) => return Err("Invalid string for address"),
        };

        let address = match Url::from_str(address_str) {
            Ok(value) => value,
            Err(_) => return Err("Invalid url for address"),
        };

        let public_key = match ffi.public_key.to_vec() {
            Ok(value) => value,
            Err(_) => return Err("public_key pointer unexpectedly null."),
        };

        Ok(sdk::Realm {
            address,
            public_key,
            id: sdk::RealmId(ffi.id),
        })
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct AuthToken {
    pub tenant: *const c_char,
    pub user: *const c_char,
    pub signature: UnmanagedBuffer<u8>,
}

impl TryFrom<AuthToken> for sdk::AuthToken {
    type Error = &'static str;

    fn try_from(ffi: AuthToken) -> Result<Self, Self::Error> {
        if ffi.tenant.is_null() {
            return Err("tenant pointer unexpectedly null.");
        }

        let tenant = match unsafe { CStr::from_ptr(ffi.tenant) }.to_str() {
            Ok(value) => value,
            Err(_) => return Err("Invalid string for tenant"),
        }
        .to_string();

        if ffi.user.is_null() {
            return Err("user pointer unexpectedly null.");
        }

        let user = match unsafe { CStr::from_ptr(ffi.user) }.to_str() {
            Ok(value) => value,
            Err(_) => return Err("Invalid string for user"),
        }
        .to_string();

        let signature = match ffi.signature.to_vec() {
            Ok(value) => value,
            Err(_) => return Err("signature pointer unexpectedly null."),
        };

        Ok(sdk::AuthToken {
            tenant,
            user,
            signature,
        })
    }
}

#[repr(C)]
pub enum ClientCreateError {
    None = 0,
    InvalidConfiguration,
    InvalidAuthToken,
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
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_create(
    configuration: Configuration,
    auth_token: AuthToken,
    http_send: HttpSendFn,
    error: *mut ClientCreateError,
) -> *mut sdk::Client<HttpClient> {
    let configuration = match sdk::Configuration::try_from(configuration) {
        Ok(value) => value,
        Err(_) => {
            *error = ClientCreateError::InvalidConfiguration;
            return ptr::null_mut();
        }
    };

    let auth_token = match sdk::AuthToken::try_from(auth_token) {
        Ok(value) => value,
        Err(_) => {
            *error = ClientCreateError::InvalidAuthToken;
            return ptr::null_mut();
        }
    };

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
    NullClient = 0,
    NullPin,
    NullSecret,
    InvalidAuth,
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
    let context = &*context;

    if client.is_null() {
        let error_ptr = Box::into_raw(Box::new(RegisterError::NullClient));
        response(context, error_ptr);
        drop(Box::from_raw(error_ptr));
        return;
    }

    let pin = match pin.to_vec() {
        Ok(value) => value,
        Err(_) => {
            let error_ptr = Box::into_raw(Box::new(RegisterError::NullPin));
            response(context, error_ptr);
            drop(Box::from_raw(error_ptr));
            return;
        }
    };

    let secret = match secret.to_vec() {
        Ok(value) => value,
        Err(_) => {
            let error_ptr = Box::into_raw(Box::new(RegisterError::NullSecret));
            response(context, error_ptr);
            drop(Box::from_raw(error_ptr));
            return;
        }
    };

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
    NullClient = 0,
    NullPin,
    InvalidAuth,
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
    let context = &*context;

    if client.is_null() {
        let error_ptr = Box::into_raw(Box::new(RecoverError::NullClient));
        response(context, UnmanagedBuffer::null(), error_ptr);
        drop(Box::from_raw(error_ptr));
        return;
    }

    let pin = match pin.to_vec() {
        Ok(value) => value,
        Err(_) => {
            let error_ptr = Box::into_raw(Box::new(RecoverError::NullPin));
            response(context, UnmanagedBuffer::null(), error_ptr);
            drop(Box::from_raw(error_ptr));
            return;
        }
    };

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
    NullClient = 0,
    InvalidAuth,
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
    let context = &*context;

    if client.is_null() {
        let error_ptr = Box::into_raw(Box::new(DeleteError::NullClient));
        response(context, error_ptr);
        drop(Box::from_raw(error_ptr));
        return;
    }

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
