use serde::{Deserialize, Serialize};
use std::{collections::HashSet, ops::Deref};

use crate::{secret_sharing::ShareIndex, PinHashingMode, Realm};
use juicebox_sdk_core::types::RealmId;

/// The parameters used to configure a [`Client`](crate::Client).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Configuration {
    /// The remote services that the client interacts with.
    ///
    /// There must be between `register_threshold` and 255 realms, inclusive.
    pub realms: Vec<Realm>,

    /// A registration will be considered successful if it's successful on at
    /// least this many realms.
    ///
    /// Must be between `recover_threshold` and `realms.len()`, inclusive.
    pub register_threshold: u32,

    /// A recovery (or an adversary) will need the cooperation of this many
    /// realms to retrieve the secret.
    ///
    /// Must be between `(realms.len() / 2).ceil()` and `realms.len()`, inclusive.
    pub recover_threshold: u32,

    /// Defines how the provided PIN will be hashed before register and recover
    /// operations. Changing modes will make previous secrets stored on the realms
    /// inaccessible with the same PIN and should not be done without re-registering
    /// secrets.
    pub pin_hashing_mode: PinHashingMode,
}

impl Configuration {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("failed to convert configuration to json")
    }
}

#[derive(Debug)]
pub(crate) struct CheckedConfiguration(Configuration);

impl CheckedConfiguration {
    pub fn from(c: Configuration) -> Self {
        assert!(
            !c.realms.is_empty(),
            "Client needs at least one realm in Configuration"
        );

        assert_eq!(
            c.realms
                .iter()
                .map(|realm| realm.id)
                .collect::<HashSet<_>>()
                .len(),
            c.realms.len(),
            "realm IDs must be unique in Configuration"
        );

        assert!(
            u32::try_from(c.realms.len()).is_ok(),
            "too many realms in Client configuration"
        );

        for realm in &c.realms {
            if let Some(public_key) = realm.public_key.as_ref() {
                assert_eq!(
                    public_key.len(),
                    32,
                    "realm public keys must be 32 bytes" // (x25519 for now)
                );
            }
        }

        assert!(
            1 <= c.recover_threshold,
            "Configuration recover_threshold must be at least 1"
        );
        assert!(
            c.recover_threshold <= c.realms.len() as u32,
            "Configuration recover_threshold cannot exceed number of realms"
        );
        assert!(
            c.recover_threshold > c.realms.len() as u32 / 2,
            "Configuration recover_threshold must contain a majority of realms"
        );

        assert!(
            c.recover_threshold <= c.register_threshold,
            "Configuration register_threshold must be at least recover_threshold"
        );
        assert!(
            c.register_threshold <= c.realms.len() as u32,
            "Configuration register_threshold cannot exceed number of realms"
        );

        // perform a fixed sorting of realms based on their id, so that shares
        // are produced in a consistent ordering for a given configuration.
        let mut sorted_realms = c.realms.clone();
        sorted_realms.sort_by(|lhs, rhs| lhs.id.cmp(&rhs.id));

        Self(Configuration {
            realms: sorted_realms,
            register_threshold: c.register_threshold,
            recover_threshold: c.recover_threshold,
            pin_hashing_mode: c.pin_hashing_mode,
        })
    }
}

impl CheckedConfiguration {
    pub fn share_index(&self, realm: &RealmId) -> Option<ShareIndex> {
        if let Some(index) = self.realms.iter().position(|r| r.id == *realm) {
            (index + 1).try_into().map(ShareIndex).ok()
        } else {
            None
        }
    }

    pub fn share_count(&self) -> u32 {
        self.realms.len().try_into().unwrap()
    }
}

impl Deref for CheckedConfiguration {
    type Target = Configuration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Configuration;

    #[test]
    fn test_configuration_json() {
        let input = r#"{
  "realms": [
    {
      "id": "0102030405060708090a0b0c0d0e0f10",
      "address": "https://juicebox.hsm.realm.address/",
      "public_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    },
    {
      "id": "2102030405060708090a0b0c0d0e0f10",
      "address": "https://your.software.realm.address/"
    },
    {
      "id": "3102030405060708090a0b0c0d0e0f10",
      "address": "https://juicebox.software.realm.address/"
    }
  ],
  "register_threshold": 3,
  "recover_threshold": 3,
  "pin_hashing_mode": "Standard2019"
}"#;
        println!("input:");
        println!("{input}");

        let configuration = Configuration::from_json(input).unwrap();
        println!("parsed:");
        println!("{configuration:#?}");

        let serialized = configuration.to_json();
        println!("serialized:");
        println!("{serialized}");

        assert_eq!(input, serialized);
    }
}
