use juicebox_sdk as sdk;

#[cfg(feature = "tokio")]
mod tokio;

#[cfg(feature = "tokio")]
pub use self::tokio::Client;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[repr(C)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(Debug)]
/// Error returned during `Client.register`
pub enum RegisterError {
    /// A realm rejected the `Client`'s auth token.
    InvalidAuth = 0,
    /// The SDK software is too old to communicate with this realm
    /// and must be upgraded.
    UpgradeRequired = 1,
    /// The tenant has exceeded their allowed number of operations. Try again
    /// later.
    RateLimitExceeded = 2,
    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    Assertion = 3,
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient = 4,
}

impl From<sdk::RegisterError> for RegisterError {
    fn from(value: sdk::RegisterError) -> Self {
        match value {
            sdk::RegisterError::InvalidAuth => Self::InvalidAuth,
            sdk::RegisterError::UpgradeRequired => Self::UpgradeRequired,
            sdk::RegisterError::Assertion => Self::Assertion,
            sdk::RegisterError::Transient => Self::Transient,
            sdk::RegisterError::RateLimitExceeded => Self::RateLimitExceeded,
        }
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
    /// The SDK software is too old to communicate with this realm
    /// and must be upgraded.
    UpgradeRequired = 3,
    /// The tenant has exceeded their allowed number of operations. Try again
    /// later.
    RateLimitExceeded = 4,
    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    Assertion = 5,
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient = 6,
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
            sdk::RecoverError::UpgradeRequired => Self {
                reason: RecoverErrorReason::UpgradeRequired,
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
            sdk::RecoverError::RateLimitExceeded => Self {
                reason: RecoverErrorReason::RateLimitExceeded,
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
    /// The SDK software is too old to communicate with this realm
    /// and must be upgraded.
    UpgradeRequired = 1,
    /// The tenant has exceeded their allowed number of operations. Try again
    /// later.
    RateLimitExceeded = 2,
    /// A software error has occurred. This request should not be retried
    /// with the same parameters. Verify your inputs, check for software
    /// updates and try again.
    Assertion = 3,
    /// A transient error in sending or receiving requests to a realm.
    /// This request may succeed by trying again with the same parameters.
    Transient = 4,
}

impl From<sdk::DeleteError> for DeleteError {
    fn from(value: sdk::DeleteError) -> Self {
        match value {
            sdk::DeleteError::InvalidAuth => DeleteError::InvalidAuth,
            sdk::DeleteError::UpgradeRequired => DeleteError::UpgradeRequired,
            sdk::DeleteError::Assertion => DeleteError::Assertion,
            sdk::DeleteError::Transient => DeleteError::Transient,
            sdk::DeleteError::RateLimitExceeded => DeleteError::RateLimitExceeded,
        }
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
