use loam_sdk as sdk;

#[cfg(feature = "tokio")]
mod tokio;

#[cfg(feature = "tokio")]
pub use self::tokio::Client;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

#[repr(C)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug)]
pub enum RegisterError {
    InvalidAuth = 0,
    Transient = 1,
    Assertion = 2,
}

impl From<sdk::RegisterError> for RegisterError {
    fn from(value: sdk::RegisterError) -> Self {
        match value {
            sdk::RegisterError::InvalidAuth => Self::InvalidAuth,
            sdk::RegisterError::Transient => Self::Transient,
            sdk::RegisterError::Assertion => Self::Assertion,
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
pub enum RecoverErrorReason {
    InvalidAuth = 0,
    InvalidPin = 1,
    NotRegistered = 2,
    Transient = 3,
    Assertion = 4,
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
            sdk::RecoverError::InvalidAuth => Self {
                reason: RecoverErrorReason::InvalidAuth,
                guesses_remaining: std::ptr::null(),
            },
            sdk::RecoverError::InvalidPin { guesses_remaining } => Self {
                reason: RecoverErrorReason::InvalidPin,
                guesses_remaining: Box::into_raw(Box::from(guesses_remaining)) as *const u16,
            },
            sdk::RecoverError::NotRegistered => Self {
                reason: RecoverErrorReason::NotRegistered,
                guesses_remaining: std::ptr::null(),
            },
            sdk::RecoverError::Transient => Self {
                reason: RecoverErrorReason::Transient,
                guesses_remaining: std::ptr::null(),
            },
            sdk::RecoverError::Assertion => Self {
                reason: RecoverErrorReason::Assertion,
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
pub enum DeleteError {
    InvalidAuth = 0,
    Transient = 1,
    Assertion = 2,
}

impl From<sdk::DeleteError> for DeleteError {
    fn from(value: sdk::DeleteError) -> Self {
        match value {
            sdk::DeleteError::InvalidAuth => DeleteError::InvalidAuth,
            sdk::DeleteError::Transient => DeleteError::Transient,
            sdk::DeleteError::Assertion => DeleteError::Assertion,
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
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Copy, Clone, Debug)]
pub enum PinHashingMode {
    /// No hashing, ensure a PIN of sufficient entropy is provided.
    None = 0,
    /// A tuned hash, secure for use on modern devices as of 2019 with low-entropy PINs.
    Standard2019 = 1,
    /// A fast hash used for testing. Do not use in production.
    FastInsecure = 2,
}

#[cfg(feature = "wasm")]
impl From<PinHashingMode> for JsValue {
    fn from(value: PinHashingMode) -> Self {
        JsValue::from(value as u8)
    }
}
