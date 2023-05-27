use crate::{PinHashingMode, Realm};

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, ops::Deref};

/// The parameters used to configure a [`Client`](crate::Client).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Configuration {
    /// The remote services that the client interacts with.
    ///
    /// There must be between `register_threshold` and 255 realms, inclusive.
    pub realms: Vec<Realm>,

    /// A registration will be considered successful if it's successful on at
    /// least this many realms.
    ///
    /// Must be between `recover_threshold` and `realms.len()`, inclusive.
    pub register_threshold: u8,

    /// A recovery (or an adversary) will need the cooperation of this many
    /// realms to retrieve the secret.
    ///
    /// Must be between `(realms.len() / 2).ceil()` and `realms.len()`, inclusive.
    pub recover_threshold: u8,

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

        // The secret sharing implementation (`sharks`) doesn't support more
        // than 255 shares.
        assert!(
            u8::try_from(c.realms.len()).is_ok(),
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
            usize::from(c.recover_threshold) <= c.realms.len(),
            "Configuration recover_threshold cannot exceed number of realms"
        );
        assert!(
            usize::from(c.recover_threshold) > c.realms.len() / 2,
            "Configuration recover_threshold must contain a majority of realms"
        );

        assert!(
            c.recover_threshold <= c.register_threshold,
            "Configuration register_threshold must be at least recover_threshold"
        );
        assert!(
            usize::from(c.register_threshold) <= c.realms.len(),
            "Configuration register_threshold cannot exceed number of realms"
        );

        Self(c)
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
