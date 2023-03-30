use crate::{http, Client, ClientError, Realm};

use loam_sdk_core::{
    marshalling,
    requests::{SecretsRequest, SecretsResponse},
};
use loam_sdk_networking::{
    requests::{ClientRequest, ClientResponse},
    rpc,
};

pub(crate) enum RequestError {
    Network,
    HttpStatus(http::ResponseStatus),
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
            Err(ClientError::Network) => Err(RequestError::Network),
            Err(ClientError::HttpStatus(sc)) => Err(RequestError::HttpStatus(sc)),
            Err(ClientError::Serialization(e)) => Err(RequestError::SerializationError(e)),
            Err(ClientError::Deserialization(e)) => Err(RequestError::DeserializationError(e)),
            Err(ClientError::HsmRpcError) => Err(RequestError::Unavailable),
        }
    }
}
