use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt;

pub trait Service {}

pub trait Rpc<S: Service>: fmt::Debug + DeserializeOwned + Serialize {
    const PATH: &'static str;
    type Response: fmt::Debug + DeserializeOwned + Serialize;
}
