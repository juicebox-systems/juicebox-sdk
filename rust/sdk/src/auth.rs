//! A trait representing generic management of tokens that grant
//! the authority to act as a particular user on a particular realm.

use async_trait::async_trait;
use juicebox_realm_api::types::{AuthToken, RealmId};
use std::collections::HashMap;

/// A trait representing generic management of tokens that grant
/// the authority to act as a particular user on a particular realm.
#[async_trait]
pub trait AuthTokenManager {
    /// Called when authentication is needed for a given realm.
    /// Ideally, you are reading from tokens you have already
    /// cached locally before making requests. However, if you
    /// do not have a token yet for this realm you can fetch one
    /// now.
    async fn get(&self, realm: &RealmId) -> Option<AuthToken>;
}

/// A trait representing generic management of tokens that grant
/// the authority to act as a particular user on a particular realm.
#[async_trait]
impl AuthTokenManager for HashMap<RealmId, AuthToken> {
    async fn get(&self, realm: &RealmId) -> Option<AuthToken> {
        self.get(realm).cloned()
    }
}
