use juicebox_sdk as sdk;

#[cfg(feature = "tokio")]
mod tokio;

#[cfg(feature = "tokio")]
pub use self::tokio::Client;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[repr(C)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug)]
/// Error returned during `Client.register`
pub enum RegisterError {
    /// A realm rejected the `Client`'s auth token.
    InvalidAuth = 0,
    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    Assertion = 1,
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient = 2,
}

impl From<sdk::RegisterError> for RegisterError {
    fn from(value: sdk::RegisterError) -> Self {
        match value {
            sdk::RegisterError::InvalidAuth => Self::InvalidAuth,
            sdk::RegisterError::Assertion => Self::Assertion,
            sdk::RegisterError::Transient => Self::Transient,
        }
    }
}

#[cfg(feature = "wasm")]
impl From<RegisterError> for JsValue {
    fn from(value: RegisterError) -> Self {
        JsValue::from(value as u8)
    }
}

#[repr(C)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Clone, Copy, Debug)]
/// Error returned during `Client.recover`
pub enum RecoverErrorReason {
    /// The secret could not be unlocked, but you can try again
    /// with a different PIN if you have guesses remaining. If no
    /// guesses remain, this secret is locked and inaccessible.
    InvalidPin = 0,
    /// The secret was not registered or not fully registered with the
    /// provided realms.
    NotRegistered = 1,
    /// A realm rejected the `Client`'s auth token.
    InvalidAuth = 2,
    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    Assertion = 3,
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient = 4,
}

#[cfg(feature = "wasm")]
impl From<RecoverErrorReason> for JsValue {
    fn from(value: RecoverErrorReason) -> Self {
        JsValue::from(value as u8)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct RecoverError {
    pub reason: RecoverErrorReason,
    /// If non-NULL, the number of guesses remaining after an Unsuccessful attempt.
    pub guesses_remaining: *const u16,
}

impl From<sdk::RecoverError> for RecoverError {
    fn from(value: sdk::RecoverError) -> Self {
        match value {
            sdk::RecoverError::InvalidPin { guesses_remaining } => Self {
                reason: RecoverErrorReason::InvalidPin,
                guesses_remaining: Box::into_raw(Box::from(guesses_remaining)) as *const u16,
            },
            sdk::RecoverError::NotRegistered => Self {
                reason: RecoverErrorReason::NotRegistered,
                guesses_remaining: std::ptr::null(),
            },
            sdk::RecoverError::InvalidAuth => Self {
                reason: RecoverErrorReason::InvalidAuth,
                guesses_remaining: std::ptr::null(),
            },
            sdk::RecoverError::Assertion => Self {
                reason: RecoverErrorReason::Assertion,
                guesses_remaining: std::ptr::null(),
            },
            sdk::RecoverError::Transient => Self {
                reason: RecoverErrorReason::Transient,
                guesses_remaining: std::ptr::null(),
            },
        }
    }
}

impl Drop for RecoverError {
    fn drop(&mut self) {
        if !self.guesses_remaining.is_null() {
            drop(unsafe { Box::from_raw(self.guesses_remaining as *mut u16) });
        }
    }
}

#[repr(C)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug)]
/// Error returned during `Client.delete`
pub enum DeleteError {
    /// A realm rejected the `Client`'s auth token.
    InvalidAuth = 0,
    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    Assertion = 1,
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient = 2,
}

impl From<sdk::DeleteError> for DeleteError {
    fn from(value: sdk::DeleteError) -> Self {
        match value {
            sdk::DeleteError::InvalidAuth => DeleteError::InvalidAuth,
            sdk::DeleteError::Assertion => DeleteError::Assertion,
            sdk::DeleteError::Transient => DeleteError::Transient,
        }
    }
}

#[cfg(feature = "wasm")]
impl From<DeleteError> for JsValue {
    fn from(value: DeleteError) -> Self {
        JsValue::from(value as u8)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub enum PinHashingMode {
    /// A tuned hash, secure for use on modern devices as of 2019 with low-entropy PINs.
    Standard2019 = 0,
    /// A fast hash used for testing. Do not use in production.
    FastInsecure = 1,
}
