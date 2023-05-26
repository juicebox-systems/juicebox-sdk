use crate::{PinHashingMode, Realm};

use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use serde_json::Value;
use std::{collections::HashSet, ops::Deref, str::FromStr};

/// The parameters used to configure a [`Client`](crate::Client).
#[derive(Clone, Debug)]
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

impl FromStr for Configuration {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl ToString for Configuration {
    fn to_string(&self) -> String {
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

impl Serialize for Configuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("JsonConfiguration", 3)?;
        let realms: Vec<Value> = self
            .realms
            .iter()
            .map(|realm| {
                let mut map = serde_json::Map::new();
                map.insert(
                    "id".to_string(),
                    serde_json::Value::String(hex::encode(realm.id.0)),
                );
                map.insert(
                    "address".to_string(),
                    serde_json::Value::String(realm.address.to_string()),
                );
                if let Some(public_key) = &realm.public_key {
                    map.insert(
                        "public_key".to_string(),
                        serde_json::Value::String(hex::encode(public_key)),
                    );
                }
                serde_json::Value::Object(map)
            })
            .collect();
        state.serialize_field("realms", &realms)?;
        state.serialize_field("register_threshold", &self.register_threshold)?;
        state.serialize_field("recover_threshold", &self.recover_threshold)?;
        state.serialize_field("pin_hashing_mode", &self.pin_hashing_mode.to_string())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Configuration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "Configuration",
            &[
                "realms",
                "register_threshold",
                "recover_threshold",
                "pin_hashing_mode",
            ],
            ConfigurationVisitor,
        )
    }
}
struct ConfigurationVisitor;

impl<'de> Visitor<'de> for ConfigurationVisitor {
    type Value = Configuration;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("struct Configuration")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut realms: Vec<Realm> = Vec::new();
        let mut register_threshold: Option<u8> = None;
        let mut recover_threshold: Option<u8> = None;
        let mut pin_hashing_mode: Option<PinHashingMode> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "realms" => {
                    let values = map.next_value::<Vec<Value>>()?;
                    for value in values {
                        let id = value["id"]
                            .as_str()
                            .ok_or_else(|| de::Error::missing_field("id"))?
                            .parse()
                            .map_err(|_| de::Error::missing_field("id"))?;

                        let address = value["address"]
                            .as_str()
                            .ok_or_else(|| de::Error::missing_field("address"))?
                            .parse()
                            .map_err(|_| de::Error::missing_field("address"))?;

                        let public_key = value["public_key"]
                            .as_str()
                            .map(hex::decode)
                            .transpose()
                            .map_err(|_| de::Error::missing_field("public_key"))?;

                        realms.push(Realm {
                            id,
                            address,
                            public_key,
                        });
                    }
                }
                "register_threshold" => {
                    register_threshold = Some(map.next_value()?);
                }
                "recover_threshold" => {
                    recover_threshold = Some(map.next_value()?);
                }
                "pin_hashing_mode" => {
                    pin_hashing_mode = Some(
                        map.next_value::<&'de str>()?
                            .parse()
                            .map_err(|_| de::Error::missing_field("pin_hashing_mode"))?,
                    );
                }
                _ => {
                    let _ = map.next_value::<Value>()?;
                }
            }
        }

        let config = Configuration {
            realms,
            register_threshold: register_threshold
                .ok_or_else(|| de::Error::missing_field("register_threshold"))?,
            recover_threshold: recover_threshold
                .ok_or_else(|| de::Error::missing_field("recover_threshold"))?,
            pin_hashing_mode: pin_hashing_mode
                .ok_or_else(|| de::Error::missing_field("pin_hashing_mode"))?,
        };

        Ok(config)
    }
}
