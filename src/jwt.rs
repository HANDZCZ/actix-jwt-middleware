use futures::future::LocalBoxFuture;
use jsonwebtoken::{DecodingKey, Validation};
use serde::de::DeserializeOwned;
use std::{
    future::{ready, Ready},
    marker::PhantomData,
    sync::Arc,
};

use actix_web::{
    body::EitherBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorBadRequest,
    http::header::{self, HeaderValue},
    Error, HttpMessage,
};

pub struct JwtMiddleware<T> {
    decoding_key: Arc<DecodingKey>,
    validation: Arc<Validation>,
    #[allow(clippy::type_complexity)]
    err_handler: Option<Arc<dyn Fn(JwtDecodeErrors) -> Error + Send + Sync>>,
    _token_data_type: PhantomData<T>,
}

impl<T> JwtMiddleware<T> {
    pub fn new(decoding_key: DecodingKey, validation: Validation) -> Self {
        Self {
            decoding_key: Arc::new(decoding_key),
            validation: Arc::new(validation),
            err_handler: None,
            _token_data_type: PhantomData,
        }
    }

    pub fn error_handler<F>(mut self, f: F) -> Self
    where
        F: Fn(JwtDecodeErrors) -> Error + Send + Sync + 'static,
    {
        self.err_handler = Some(Arc::new(f));
        self
    }
}

impl<S, B, T> Transform<S, ServiceRequest> for JwtMiddleware<T>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    T: DeserializeOwned + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = JwtService<S, T>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtService {
            service,
            decoding_key: self.decoding_key.clone(),
            validation: self.validation.clone(),
            err_handler: self.err_handler.clone(),
            _token_data_type: PhantomData,
        }))
    }
}

pub struct JwtService<S, T> {
    service: S,
    decoding_key: Arc<DecodingKey>,
    validation: Arc<Validation>,
    #[allow(clippy::type_complexity)]
    err_handler: Option<Arc<dyn Fn(JwtDecodeErrors) -> Error + Send + Sync>>,
    _token_data_type: PhantomData<T>,
}

#[allow(clippy::enum_variant_names)]
pub enum JwtDecodeErrors {
    InvalidAuthHeader,
    InvalidJWTHeader,
    InvalidJWTToken(jsonwebtoken::errors::Error),
}

impl JwtDecodeErrors {
    pub fn to_error_string(&self) -> String {
        match self {
            JwtDecodeErrors::InvalidAuthHeader => {
                "Invalid authorization header - header contains invalid ASCII characters".into()
            }
            JwtDecodeErrors::InvalidJWTHeader => "Invalid authorization header - header need to have this format 'Bearer HEADER.PAYLOAD.SIGNATURE' where all three parts need to be base64 encoded and separated by a dot".into(),
            JwtDecodeErrors::InvalidJWTToken(e) => format!("Invalid JWT token - an error occurred when decoding token: {}", e),
        }
    }
}

fn decode_jwt<T: DeserializeOwned>(
    header_value: &HeaderValue,
    decoding_key: &DecodingKey,
    validation: &Validation,
) -> Result<T, JwtDecodeErrors> {
    let Ok(header_value) = header_value.to_str() else {
        return Err(JwtDecodeErrors::InvalidAuthHeader);
    };
    if !header_value.starts_with("Bearer ") {
        return Err(JwtDecodeErrors::InvalidJWTHeader);
    }
    match jsonwebtoken::decode::<T>(&header_value[7..], decoding_key, validation) {
        Ok(data) => Ok(data.claims),
        Err(e) => Err(JwtDecodeErrors::InvalidJWTToken(e)),
    }
}

impl<S, B, T> Service<ServiceRequest> for JwtService<S, T>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    T: DeserializeOwned + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth_header_value = req.headers().get(header::AUTHORIZATION).cloned();

        if let Some(auth_header_value) = auth_header_value {
            let claims = decode_jwt::<T>(&auth_header_value, &self.decoding_key, &self.validation);
            match claims {
                Ok(token_data) => {
                    req.extensions_mut().insert(token_data);
                }
                Err(e) => {
                    return Box::pin(ready(Ok(req
                        .error_response({
                            if let Some(err_handler) = self.err_handler.clone() {
                                (err_handler)(e)
                            } else {
                                ErrorBadRequest(e.to_error_string())
                            }
                        })
                        .map_into_right_body())));
                }
            }
        };

        let fut = self.service.call(req);
        Box::pin(async move { Ok(fut.await?.map_into_left_body()) })
    }
}
