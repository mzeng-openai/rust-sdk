use std::collections::HashMap;

use http::{HeaderName, HeaderValue};

use crate::transport::{
    auth::{AuthClient, AuthError},
    streamable_http_client::{StreamableHttpClient, StreamableHttpError},
};

impl<C> AuthClient<C>
where
    C: StreamableHttpClient + Send + Sync,
{
    /// Run `call` with a token when one is available, reacting to the
    /// server's auth verdict instead of requiring credentials up front:
    ///
    /// - no usable credentials → the request goes out unauthenticated, and a
    ///   401 propagates as [`StreamableHttpError::AuthRequired`] carrying the
    ///   `WWW-Authenticate` challenge for the caller to authorize with;
    /// - a token the server rejects (e.g. revoked) → one silent refresh, one
    ///   retry, then the challenge propagates.
    async fn call_reacting_to_challenges<T, F, Fut>(
        &self,
        auth_token: Option<String>,
        call: F,
    ) -> Result<T, StreamableHttpError<C::Error>>
    where
        F: Fn(Option<String>) -> Fut,
        Fut: Future<Output = Result<T, StreamableHttpError<C::Error>>>,
    {
        // Missing credentials are not an error in the reactive model: the
        // request goes out unauthenticated and the server's 401 challenge
        // drives authorization.
        let auth_token = match auth_token {
            None => match self.get_access_token().await {
                Ok(token) => Some(token),
                Err(AuthError::AuthorizationRequired) => None,
                Err(error) => return Err(error.into()),
            },
            token => token,
        };
        match call(auth_token.clone()).await {
            Err(StreamableHttpError::AuthRequired(challenge)) => {
                // One silent recovery attempt: refresh the rejected token and
                // retry only when the refresh actually produced a new one.
                let Some(sent_token) = auth_token else {
                    return Err(StreamableHttpError::AuthRequired(challenge));
                };
                let refreshed = self.access_token_task(Some(sent_token.clone())).await;
                match refreshed {
                    Ok(fresh_token) if fresh_token != sent_token => call(Some(fresh_token)).await,
                    Ok(_) | Err(AuthError::AuthorizationRequired) => {
                        Err(StreamableHttpError::AuthRequired(challenge))
                    }
                    Err(error) => Err(error.into()),
                }
            }
            result => result,
        }
    }
}

impl<C> StreamableHttpClient for AuthClient<C>
where
    C: StreamableHttpClient + Send + Sync,
{
    type Error = C::Error;

    async fn delete_session(
        &self,
        uri: std::sync::Arc<str>,
        session_id: std::sync::Arc<str>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), crate::transport::streamable_http_client::StreamableHttpError<Self::Error>>
    {
        self.call_reacting_to_challenges(auth_token, |token| {
            let uri = uri.clone();
            let session_id = session_id.clone();
            let custom_headers = custom_headers.clone();
            async move {
                self.http_client
                    .delete_session(uri, session_id, token, custom_headers)
                    .await
            }
        })
        .await
    }

    async fn get_stream(
        &self,
        uri: std::sync::Arc<str>,
        session_id: Option<std::sync::Arc<str>>,
        last_event_id: Option<String>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<
        futures::stream::BoxStream<'static, Result<sse_stream::Sse, sse_stream::Error>>,
        crate::transport::streamable_http_client::StreamableHttpError<Self::Error>,
    > {
        self.call_reacting_to_challenges(auth_token, |token| {
            let uri = uri.clone();
            let session_id = session_id.clone();
            let last_event_id = last_event_id.clone();
            let custom_headers = custom_headers.clone();
            async move {
                self.http_client
                    .get_stream(uri, session_id, last_event_id, token, custom_headers)
                    .await
            }
        })
        .await
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: std::sync::Arc<str>,
        session_id: Option<std::sync::Arc<str>>,
        last_event_id: Option<String>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<
        futures::stream::BoxStream<'static, Result<sse_stream::Sse, sse_stream::Error>>,
        crate::transport::streamable_http_client::StreamableHttpError<Self::Error>,
    > {
        self.call_reacting_to_challenges(auth_token, |token| {
            let uri = uri.clone();
            let session_id = session_id.clone();
            let last_event_id = last_event_id.clone();
            let custom_headers = custom_headers.clone();
            async move {
                self.http_client
                    .get_stream_with_max_sse_event_size(
                        uri,
                        session_id,
                        last_event_id,
                        token,
                        custom_headers,
                        max_sse_event_size,
                    )
                    .await
            }
        })
        .await
    }

    async fn post_message(
        &self,
        uri: std::sync::Arc<str>,
        message: crate::model::ClientJsonRpcMessage,
        session_id: Option<std::sync::Arc<str>>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<
        crate::transport::streamable_http_client::StreamableHttpPostResponse,
        StreamableHttpError<Self::Error>,
    > {
        self.call_reacting_to_challenges(auth_token, |token| {
            let uri = uri.clone();
            let message = message.clone();
            let session_id = session_id.clone();
            let custom_headers = custom_headers.clone();
            async move {
                self.http_client
                    .post_message(uri, message, session_id, token, custom_headers)
                    .await
            }
        })
        .await
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        uri: std::sync::Arc<str>,
        message: crate::model::ClientJsonRpcMessage,
        session_id: Option<std::sync::Arc<str>>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<
        crate::transport::streamable_http_client::StreamableHttpPostResponse,
        StreamableHttpError<Self::Error>,
    > {
        self.call_reacting_to_challenges(auth_token, |token| {
            let uri = uri.clone();
            let message = message.clone();
            let session_id = session_id.clone();
            let custom_headers = custom_headers.clone();
            async move {
                self.http_client
                    .post_message_with_max_sse_event_size(
                        uri,
                        message,
                        session_id,
                        token,
                        custom_headers,
                        max_sse_event_size,
                    )
                    .await
            }
        })
        .await
    }
}

#[cfg(all(test, feature = "transport-streamable-http-client-reqwest"))]
mod tests {
    use super::*;
    use crate::transport::{
        auth::{
            AuthorizationManager, AuthorizationMetadata, CredentialStore, InMemoryCredentialStore,
            StoredCredentials,
        },
        streamable_http_client::AuthRequiredError,
    };

    fn credentials(access_token: &str) -> StoredCredentials {
        StoredCredentials::new(
            "client".into(),
            Some(
                serde_json::from_value(serde_json::json!({
                    "access_token": access_token,
                    "token_type": "Bearer",
                }))
                .unwrap(),
            ),
            Vec::new(),
            None,
        )
    }

    async fn auth_client(store: impl CredentialStore + 'static) -> AuthClient<reqwest::Client> {
        let mut manager = AuthorizationManager::new("http://localhost").await.unwrap();
        manager.set_metadata(AuthorizationMetadata {
            authorization_endpoint: "http://localhost/authorize".into(),
            token_endpoint: "http://localhost/token".into(),
            ..Default::default()
        });
        manager.configure_client_id("client").unwrap();
        manager.set_credential_store(store);
        AuthClient::new(reqwest::Client::new(), manager)
    }

    #[tokio::test]
    async fn delayed_unauthorized_response_reuses_a_newer_token() {
        let store = InMemoryCredentialStore::new();
        store.save(credentials("old-token")).await.unwrap();
        let client = auth_client(store.clone()).await;

        client
            .call_reacting_to_challenges(None, |token| {
                let store = store.clone();
                async move {
                    match token.as_deref() {
                        Some("old-token") => {
                            // Another request saves a fresh token before this
                            // request's challenge reaches the authorization manager.
                            store.save(credentials("new-token")).await.unwrap();
                            Err(StreamableHttpError::AuthRequired(AuthRequiredError::new(
                                "Bearer".into(),
                            )))
                        }
                        Some("new-token") => Ok(()),
                        unexpected => panic!("unexpected token: {unexpected:?}"),
                    }
                }
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reactive_refresh_preserves_credential_guard_failure() {
        struct UnavailableGuardStore;

        #[async_trait::async_trait]
        impl CredentialStore for UnavailableGuardStore {
            async fn load(&self) -> Result<Option<StoredCredentials>, AuthError> {
                unreachable!("guard failure must stop the credential reload")
            }

            async fn save(&self, _: StoredCredentials) -> Result<(), AuthError> {
                unreachable!("guard failure must stop the credential save")
            }

            async fn clear(&self) -> Result<(), AuthError> {
                unreachable!("refresh must not clear credentials")
            }

            async fn acquire_refresh_guard(
                &self,
            ) -> Result<Option<crate::transport::auth::CredentialRefreshGuard>, AuthError>
            {
                Err(AuthError::InternalError(
                    "credential guard unavailable".into(),
                ))
            }
        }

        let client = auth_client(UnavailableGuardStore).await;
        let error = client
            .call_reacting_to_challenges(Some("old-token".into()), |_| async {
                Err::<(), _>(StreamableHttpError::AuthRequired(AuthRequiredError::new(
                    "Bearer".into(),
                )))
            })
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            StreamableHttpError::Auth(AuthError::InternalError(message))
                if message == "credential guard unavailable"
        ));
    }
}
