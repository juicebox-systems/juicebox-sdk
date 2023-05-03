pub mod array;
pub mod http;

use libc::{c_char, c_void};
use loam_sdk as sdk;
use loam_sdk_bridge::{Client, DeleteError, PinHashingMode, RecoverError, RegisterError};
use std::{ffi::CStr, ptr, str::FromStr};
use url::Url;

use crate::array::{ManagedArray, UnmanagedArray};
use crate::http::{HttpClient, HttpSendFn};

#[derive(Debug)]
#[repr(C)]
pub struct Configuration {
    pub realms: UnmanagedArray<Realm>,
    pub register_threshold: u8,
    pub recover_threshold: u8,
    pub pin_hashing_mode: PinHashingMode,
}

impl From<&Configuration> for sdk::Configuration {
    fn from(ffi: &Configuration) -> Self {
        let realms = ffi.realms.as_slice().iter().map(sdk::Realm::from).collect();

        sdk::Configuration {
            realms,
            register_threshold: ffi.register_threshold,
            recover_threshold: ffi.recover_threshold,
            pin_hashing_mode: sdk::PinHashingMode::from(ffi.pin_hashing_mode as u8),
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

/// Constructs a new opaque `LoamClient`.
///
/// # Arguments
///
/// * `configuration` – Represents the current configuration. The configuration
/// provided must include at least one `LoamRealm`.
/// * `previous_configurations` – Represents any other configurations you have
/// previously registered with that you may not yet have migrated the data from.
/// During `loam_client_recover`, they will be tried if the current user has not yet
/// registered on the current configuration. These should be ordered from most recently
/// to least recently used.
/// * `auth_token` – Represents the authority to act as a particular user
/// and should be valid for the lifetime of the `LoamClient`.
/// * `http_send` – A function pointer `http_send` that will be called when the client
/// wishes to make a network request. The appropriate request should be executed by you,
/// and the the response provided to the response function pointer. This send
/// should be performed asynchronously. `http_send` should not block on
/// performing the request, and the response should be returned to the
/// `response` function pointer argument when the asynchronous work has
/// completed. The request parameter is only valid for the lifetime of the
/// `http_send` function and should not be accessed after returning from the
/// function.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_create(
    configuration: Configuration,
    previous_configurations: UnmanagedArray<Configuration>,
    auth_token: *const c_char,
    http_send: HttpSendFn,
) -> *mut Client<HttpClient> {
    let configuration = sdk::Configuration::from(&configuration);
    let previous_configurations = previous_configurations
        .as_slice()
        .iter()
        .map(sdk::Configuration::from)
        .collect();
    let auth_token = sdk::AuthToken::from(
        unsafe { CStr::from_ptr(auth_token) }
            .to_str()
            .expect("invalid string for auth token")
            .to_owned(),
    );
    let sdk = sdk::Client::with_tokio(
        configuration,
        previous_configurations,
        auth_token,
        HttpClient::new(http_send),
    );
    Box::into_raw(Box::new(Client::new(sdk)))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_destroy(client: *mut Client<HttpClient>) {
    assert!(!client.is_null());
    drop(Box::from_raw(client))
}

/// Stores a new PIN-protected secret on the configured realms.
///
/// # Note
///
/// The provided secret must have a maximum length of 128-bytes.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_register(
    client: *mut Client<HttpClient>,
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
            &sdk::Pin::from(pin),
            &sdk::UserSecret::from(secret),
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

/// Retrieves a PIN-protected secret from the configured realms, or falls
/// back to the previous realms if the current realms do not have a secret
/// registered.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_recover(
    client: *mut Client<HttpClient>,
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
        match client
            .runtime
            .block_on(client.sdk.recover(&sdk::Pin::from(pin)))
        {
            Ok(secret) => {
                let mut secret = ManagedArray(secret.expose_secret().to_vec());
                (response)(context, secret.unmanaged_borrow(), ptr::null());
            }
            Err(err) => {
                let error = RecoverError::from(err);
                (response)(context, UnmanagedArray::null(), &error);
            }
        };
    });
}

/// Deletes the registered secret for this user, if any.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn loam_client_delete(
    client: *mut Client<HttpClient>,
    context: *const c_void,
    response: extern "C" fn(context: &c_void, error: *const DeleteError),
) {
    assert!(!client.is_null());
    let context = &*context;
    let client = &*client;

    client.runtime.spawn_blocking(move || {
        match client.runtime.block_on(client.sdk.delete()) {
            Ok(_) => (response)(context, ptr::null()),
            Err(err) => {
                let error = DeleteError::from(err);
                (response)(context, &error);
            }
        };
    });
}
