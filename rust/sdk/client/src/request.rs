use crate::{http, Client, Realm};

use loam_sdk_core::{
    marshalling,
    requests::{ClientRequest, ClientResponse, SecretsRequest, SecretsResponse},
};
use loam_sdk_networking::rpc::{self, RpcError};

pub(crate) enum RequestError {
    Network,
    HttpStatus(u16),
    DeserializationError(marshalling::DeserializationError),
    SerializationError(marshalling::SerializationError),
    Unavailable,
    InvalidAuth,
}

impl<Http: http::Client> Client<Http> {
    pub(crate) async fn make_request(
        &self,
        realm: &Realm,
        request: SecretsRequest,
    ) -> Result<SecretsResponse, RequestError> {
        match rpc::send(
            &self.http,
            &realm.address,
            ClientRequest {
                realm: realm.id,
                auth_token: self.auth_token.clone(),
                request,
            },
        )
        .await
        {
            Ok(ClientResponse::Ok(response)) => Ok(response),
            Ok(ClientResponse::Unavailable) => Err(RequestError::Unavailable),
            Ok(ClientResponse::InvalidAuth) => Err(RequestError::InvalidAuth),
            Err(RpcError::Network) => Err(RequestError::Network),
            Err(RpcError::HttpStatus(sc)) => Err(RequestError::HttpStatus(sc)),
            Err(RpcError::Serialization(e)) => Err(RequestError::SerializationError(e)),
            Err(RpcError::Deserialization(e)) => Err(RequestError::DeserializationError(e)),
        }
    }
}
