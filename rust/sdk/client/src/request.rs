use crate::http::send_rpc;
use crate::{HttpClient, Loam, Realm};
use loam_sdk_core::{
    marshalling, ClientError, ClientRequest, ClientResponse, HttpResponseStatus, SecretsRequest,
    SecretsResponse,
};
use std::str::FromStr;
use url::Url;

pub(crate) enum RequestError {
    Network,
    HttpStatus(HttpResponseStatus),
    DeserializationError(marshalling::DeserializationError),
    SerializationError(marshalling::SerializationError),
    Unavailable,
    InvalidAuth,
    InvalidRealmUrl,
}

impl<Http: HttpClient> Loam<Http> {
    pub(crate) async fn make_request(
        &self,
        realm: &Realm,
        request: SecretsRequest,
    ) -> Result<SecretsResponse, RequestError> {
        match send_rpc(
            &self.http,
            Url::from_str(&realm.address).map_err(|_| RequestError::InvalidRealmUrl)?,
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
            Err(ClientError::InvalidUrl) => Err(RequestError::InvalidRealmUrl),
        }
    }
}
