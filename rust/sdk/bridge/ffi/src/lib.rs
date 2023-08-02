pub mod array;
pub mod auth;
pub mod http;

use auth::{AuthTokenGetFn, AuthTokenManager};
use juicebox_sdk as sdk;
use juicebox_sdk_bridge::{Client, DeleteError, PinHashingMode, RecoverError, RegisterError};
use libc::{c_char, c_void};
use std::ffi::CString;
use std::sync::Once;
use std::{ffi::CStr, ptr, str::FromStr};
use url::Url;

use crate::array::{ManagedArray, UnmanagedArray};
use crate::http::{HttpClient, HttpSendFn};

#[derive(Debug)]
#[repr(C)]
pub struct Realm {
    pub id: [u8; 16],
    pub address: *const c_char,
    pub public_key: *const UnmanagedArray<u8>,
}

impl From<&Realm> for sdk::Realm {
    fn from(ffi: &Realm) -> Self {
        assert!(!ffi.address.is_null());
        let address_str = unsafe { CStr::from_ptr(ffi.address) }
            .to_str()
            .expect("invalid string for address");
        let address = Url::from_str(address_str).expect("invalid URL for address");

        let public_key = if ffi.public_key.is_null() {
            None
        } else {
            Some(unsafe { (*ffi.public_key).to_vec() })
        };

        sdk::Realm {
            id: sdk::RealmId(ffi.id),
            address,
            public_key,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Configuration(sdk::Configuration);

/// Constructs a new opaque `JuiceboxClient`.
///
/// # Arguments
///
/// * `configuration` – Represents the current configuration. The configuration
/// provided must include at least one `JuiceboxRealm`.
/// * `previous_configurations` – Represents any other configurations you have
/// previously registered with that you may not yet have migrated the data from.
/// During `juicebox_client_recover`, they will be tried if the current user has not yet
/// registered on the current configuration. These should be ordered from most recently
/// to least recently used.
/// * `auth_token` – Represents the authority to act as a particular user
/// and should be valid for the lifetime of the `JuiceboxClient`.
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
pub unsafe extern "C" fn juicebox_client_create(
    configuration: *mut Configuration,
    previous_configurations: UnmanagedArray<*mut Configuration>,
    auth_token_get: AuthTokenGetFn,
    http_send: HttpSendFn,
) -> *mut Client<HttpClient, AuthTokenManager> {
    assert!(!configuration.is_null());
    let previous_configurations = previous_configurations
        .as_slice()
        .iter()
        .map(|configuration| {
            assert!(!configuration.is_null());
            (*(*configuration)).0.to_owned()
        })
        .collect();
    let sdk = sdk::ClientBuilder::new()
        .tokio_sleeper()
        .configuration((*configuration).0.to_owned())
        .previous_configurations(previous_configurations)
        .auth_token_manager(AuthTokenManager::new(auth_token_get))
        .http(HttpClient::new(http_send))
        .build();
    Box::into_raw(Box::new(Client::new(sdk)))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_client_destroy(
    client: *mut Client<HttpClient, AuthTokenManager>,
) {
    assert!(!client.is_null());
    drop(Box::from_raw(client))
}

static VERSION_INIT: Once = Once::new();
static mut VERSION: *const c_char = ptr::null();

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_sdk_version() -> *const c_char {
    VERSION_INIT.call_once(|| {
        VERSION = CString::new(sdk::VERSION).unwrap().into_raw();
    });
    VERSION
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_configuration_create(
    realms: UnmanagedArray<Realm>,
    register_threshold: u32,
    recover_threshold: u32,
    pin_hashing_mode: PinHashingMode,
) -> *mut Configuration {
    Box::into_raw(Box::new(Configuration(sdk::Configuration {
        realms: realms.as_slice().iter().map(sdk::Realm::from).collect(),
        register_threshold,
        recover_threshold,
        pin_hashing_mode: sdk::PinHashingMode::from(pin_hashing_mode as u8),
    })))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_configuration_create_from_json(
    json: *const c_char,
) -> *mut Configuration {
    assert!(!json.is_null());
    let json_str = unsafe { CStr::from_ptr(json) }
        .to_str()
        .expect("invalid string for address");
    Box::into_raw(Box::new(Configuration(
        sdk::Configuration::from_json(json_str).expect("invalid configuration json"),
    )))
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_configuration_destroy(configuration: *mut Configuration) {
    assert!(!configuration.is_null());
    drop(Box::from_raw(configuration));
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_configurations_are_equal(
    configuration1: *mut Configuration,
    configuration2: *mut Configuration,
) -> bool {
    if configuration1.is_null() && configuration2.is_null() {
        return true;
    }
    if configuration1.is_null() || configuration2.is_null() {
        return false;
    }
    *configuration1 == *configuration2
}

/// Stores a new PIN-protected secret on the configured realms.
///
/// # Note
///
/// The provided secret must have a maximum length of 128-bytes.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn juicebox_client_register(
    client: *mut Client<HttpClient, AuthTokenManager>,
    context: *const c_void,
    pin: UnmanagedArray<u8>,
    secret: UnmanagedArray<u8>,
    info: UnmanagedArray<u8>,
    num_guesses: u16,
    response: extern "C" fn(context: &c_void, error: *const RegisterError),
) {
    assert!(!client.is_null());
    let context = &*context;
    let pin = pin.to_vec();
    let secret = secret.to_vec();
    let info = info.to_vec();
    let client = &*client;

    client.runtime.spawn_blocking(move || {
        match client.runtime.block_on(client.sdk.register(
            &sdk::Pin::from(pin),
            &sdk::UserSecret::from(secret),
            &sdk::UserInfo::from(info),
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
pub unsafe extern "C" fn juicebox_client_recover(
    client: *mut Client<HttpClient, AuthTokenManager>,
    context: *const c_void,
    pin: UnmanagedArray<u8>,
    info: UnmanagedArray<u8>,
    response: extern "C" fn(
        context: &c_void,
        secret: UnmanagedArray<u8>,
        error: *const RecoverError,
    ),
) {
    assert!(!client.is_null());
    let context = &*context;
    let pin = pin.to_vec();
    let info = info.to_vec();
    let client = &*client;

    client.runtime.spawn_blocking(move || {
        match client.runtime.block_on(
            client
                .sdk
                .recover(&sdk::Pin::from(pin), &sdk::UserInfo::from(info)),
        ) {
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
pub unsafe extern "C" fn juicebox_client_delete(
    client: *mut Client<HttpClient, AuthTokenManager>,
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
