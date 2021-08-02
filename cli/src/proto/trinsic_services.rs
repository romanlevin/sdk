#[doc = r" Generated client implementations."]
pub mod debugging_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    pub struct DebuggingClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl DebuggingClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> DebuggingClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        pub async fn call_empty(
            &mut self,
            request: impl tonic::IntoRequest<super::super::google::protobuf::Empty>,
        ) -> Result<tonic::Response<super::super::google::protobuf::Empty>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/trinsic.services.Debugging/CallEmpty");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn call_empty_auth(
            &mut self,
            request: impl tonic::IntoRequest<super::super::google::protobuf::Empty>,
        ) -> Result<tonic::Response<super::super::google::protobuf::Empty>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/trinsic.services.Debugging/CallEmptyAuth");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for DebuggingClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for DebuggingClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "DebuggingClient {{ ... }}")
        }
    }
}
#[derive(::serde::Serialize, ::serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct JsonPayload {
    #[prost(oneof = "json_payload::Json", tags = "1, 2, 3")]
    pub json: ::core::option::Option<json_payload::Json>,
}
/// Nested message and enum types in `JsonPayload`.
pub mod json_payload {
    #[derive(::serde::Serialize, ::serde::Deserialize, Clone, PartialEq, ::prost::Oneof)]
    pub enum Json {
        #[prost(message, tag = "1")]
        JsonStruct(super::super::super::google::protobuf::Struct),
        #[prost(string, tag = "2")]
        JsonString(::prost::alloc::string::String),
        #[prost(bytes, tag = "3")]
        JsonBytes(::prost::alloc::vec::Vec<u8>),
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ResponseStatus {
    Success = 0,
    WalletAccessDenied = 10,
    WalletExists = 11,
    ItemNotFound = 20,
    SerializationError = 200,
    UnknownError = 100,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum JsonFormat {
    Protobuf = 0,
    Binary = 1,
    String = 2,
}
#[doc = r" Generated client implementations."]
pub mod common_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    pub struct CommonClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl CommonClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> CommonClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        pub async fn request(
            &mut self,
            request: impl tonic::IntoRequest<super::super::super::pbmse::EncryptedMessage>,
        ) -> Result<tonic::Response<super::super::super::pbmse::EncryptedMessage>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/trinsic.services.Common/Request");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for CommonClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for CommonClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "CommonClient {{ ... }}")
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IssueRequest {
    #[prost(message, optional, tag = "1")]
    pub document: ::core::option::Option<JsonPayload>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IssueResponse {
    #[prost(message, optional, tag = "1")]
    pub document: ::core::option::Option<JsonPayload>,
}
/// Create Proof
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateProofRequest {
    #[prost(message, optional, tag = "1")]
    pub reveal_document: ::core::option::Option<JsonPayload>,
    #[prost(string, tag = "2")]
    pub document_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateProofResponse {
    #[prost(message, optional, tag = "1")]
    pub proof_document: ::core::option::Option<JsonPayload>,
}
/// Verify Proof
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerifyProofRequest {
    #[prost(message, optional, tag = "1")]
    pub proof_document: ::core::option::Option<JsonPayload>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerifyProofResponse {
    #[prost(bool, tag = "1")]
    pub valid: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendRequest {
    #[prost(message, optional, tag = "100")]
    pub document: ::core::option::Option<JsonPayload>,
    #[prost(oneof = "send_request::DeliveryMethod", tags = "1, 2, 3")]
    pub delivery_method: ::core::option::Option<send_request::DeliveryMethod>,
}
/// Nested message and enum types in `SendRequest`.
pub mod send_request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum DeliveryMethod {
        #[prost(string, tag = "1")]
        Email(::prost::alloc::string::String),
        #[prost(string, tag = "2")]
        DidUri(::prost::alloc::string::String),
        #[prost(message, tag = "3")]
        DidcommInvitation(super::JsonPayload),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SendResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
}
#[doc = r" Generated client implementations."]
pub mod credential_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    pub struct CredentialClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl CredentialClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> CredentialClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        pub async fn issue(
            &mut self,
            request: impl tonic::IntoRequest<super::IssueRequest>,
        ) -> Result<tonic::Response<super::IssueResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/trinsic.services.Credential/Issue");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn create_proof(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateProofRequest>,
        ) -> Result<tonic::Response<super::CreateProofResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/trinsic.services.Credential/CreateProof");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn verify_proof(
            &mut self,
            request: impl tonic::IntoRequest<super::VerifyProofRequest>,
        ) -> Result<tonic::Response<super::VerifyProofResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/trinsic.services.Credential/VerifyProof");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn send(
            &mut self,
            request: impl tonic::IntoRequest<super::SendRequest>,
        ) -> Result<tonic::Response<super::SendResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/trinsic.services.Credential/Send");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for CredentialClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for CredentialClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "CredentialClient {{ ... }}")
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateWalletRequest {
    #[prost(string, tag = "1")]
    pub controller: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub description: ::prost::alloc::string::String,
    /// (Optional) Supply an invitation id to associate this caller profile
    /// to an existing cloud wallet.
    #[prost(string, tag = "3")]
    pub security_code: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateWalletResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
    #[prost(string, tag = "2")]
    pub wallet_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub capability: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub invoker: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConnectRequest {
    #[prost(oneof = "connect_request::ContactMethod", tags = "5, 6")]
    pub contact_method: ::core::option::Option<connect_request::ContactMethod>,
}
/// Nested message and enum types in `ConnectRequest`.
pub mod connect_request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ContactMethod {
        #[prost(string, tag = "5")]
        Email(::prost::alloc::string::String),
        #[prost(string, tag = "6")]
        Phone(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConnectResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvitationToken {
    #[prost(string, tag = "1")]
    pub security_code: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub wallet_id: ::prost::alloc::string::String,
    #[prost(oneof = "invitation_token::ContactMethod", tags = "5, 6")]
    pub contact_method: ::core::option::Option<invitation_token::ContactMethod>,
}
/// Nested message and enum types in `InvitationToken`.
pub mod invitation_token {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ContactMethod {
        #[prost(string, tag = "5")]
        Email(::prost::alloc::string::String),
        #[prost(string, tag = "6")]
        Phone(::prost::alloc::string::String),
    }
}
///
///Stores profile data for accessing a wallet.
///This result should be stored somewhere safe,
///as it contains private key information.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WalletProfile {
    #[prost(message, optional, tag = "1")]
    pub did_document: ::core::option::Option<JsonPayload>,
    #[prost(string, tag = "2")]
    pub wallet_id: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub invoker: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub capability: ::prost::alloc::string::String,
    #[prost(bytes = "vec", tag = "5")]
    pub invoker_jwk: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GrantAccessRequest {
    #[prost(string, tag = "1")]
    pub wallet_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub did: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GrantAccessResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RevokeAccessRequest {
    #[prost(string, tag = "1")]
    pub wallet_id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub did: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RevokeAccessResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
}
// GetProviderConfiguration

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProviderConfigurationResponse {
    #[prost(message, optional, tag = "1")]
    pub did_document: ::core::option::Option<JsonPayload>,
    #[prost(string, tag = "2")]
    pub key_agreement_key_id: ::prost::alloc::string::String,
}
// Search

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SearchRequest {
    #[prost(string, tag = "1")]
    pub query: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SearchResponse {
    #[prost(message, repeated, tag = "1")]
    pub items: ::prost::alloc::vec::Vec<JsonPayload>,
    #[prost(bool, tag = "2")]
    pub has_more: bool,
}
// InsertItem

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InsertItemRequest {
    #[prost(message, optional, tag = "1")]
    pub item: ::core::option::Option<JsonPayload>,
    #[prost(string, tag = "2")]
    pub item_type: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InsertItemResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
    #[prost(string, tag = "2")]
    pub item_id: ::prost::alloc::string::String,
}
#[doc = r" Generated client implementations."]
pub mod wallet_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    pub struct WalletClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl WalletClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> WalletClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        pub async fn get_provider_configuration(
            &mut self,
            request: impl tonic::IntoRequest<super::super::google::protobuf::Empty>,
        ) -> Result<tonic::Response<super::GetProviderConfigurationResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.Wallet/GetProviderConfiguration",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn connect_external_identity(
            &mut self,
            request: impl tonic::IntoRequest<super::ConnectRequest>,
        ) -> Result<tonic::Response<super::ConnectResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.Wallet/ConnectExternalIdentity",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn create_wallet(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateWalletRequest>,
        ) -> Result<tonic::Response<super::CreateWalletResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/trinsic.services.Wallet/CreateWallet");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn create_wallet_with_workflow(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateWalletRequest>,
        ) -> Result<tonic::Response<super::CreateWalletResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.Wallet/CreateWalletWithWorkflow",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn create_wallet_encrypted(
            &mut self,
            request: impl tonic::IntoRequest<super::super::super::pbmse::EncryptedMessage>,
        ) -> Result<tonic::Response<super::super::super::pbmse::EncryptedMessage>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.Wallet/CreateWalletEncrypted",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn search(
            &mut self,
            request: impl tonic::IntoRequest<super::SearchRequest>,
        ) -> Result<tonic::Response<super::SearchResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/trinsic.services.Wallet/Search");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn insert_item(
            &mut self,
            request: impl tonic::IntoRequest<super::InsertItemRequest>,
        ) -> Result<tonic::Response<super::InsertItemResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/trinsic.services.Wallet/InsertItem");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn grant_access(
            &mut self,
            request: impl tonic::IntoRequest<super::GrantAccessRequest>,
        ) -> Result<tonic::Response<super::GrantAccessResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/trinsic.services.Wallet/GrantAccess");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn revoke_access(
            &mut self,
            request: impl tonic::IntoRequest<super::RevokeAccessRequest>,
        ) -> Result<tonic::Response<super::RevokeAccessResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/trinsic.services.Wallet/RevokeAccess");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for WalletClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for WalletClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "WalletClient {{ ... }}")
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InviteRequest {
    #[prost(enumeration = "ParticipantType", tag = "1")]
    pub participant: i32,
    #[prost(string, tag = "2")]
    pub description: ::prost::alloc::string::String,
    #[prost(oneof = "invite_request::ContactMethod", tags = "5, 6, 7")]
    pub contact_method: ::core::option::Option<invite_request::ContactMethod>,
}
/// Nested message and enum types in `InviteRequest`.
pub mod invite_request {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DidCommInvitation {}
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ContactMethod {
        #[prost(string, tag = "5")]
        Email(::prost::alloc::string::String),
        #[prost(string, tag = "6")]
        Phone(::prost::alloc::string::String),
        #[prost(message, tag = "7")]
        DidcommInvitation(DidCommInvitation),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InviteResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
    #[prost(string, tag = "10")]
    pub invitation_id: ::prost::alloc::string::String,
}
/// Request details for the status of onboarding
/// an individual or organization.
/// The referenece_id passed is the response from the
/// `Onboard` method call
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvitationStatusRequest {
    #[prost(string, tag = "1")]
    pub invitation_id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvitationStatusResponse {
    #[prost(enumeration = "invitation_status_response::Status", tag = "1")]
    pub status: i32,
    #[prost(string, tag = "2")]
    pub status_details: ::prost::alloc::string::String,
}
/// Nested message and enum types in `InvitationStatusResponse`.
pub mod invitation_status_response {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum Status {
        /// Onboarding resulted in error
        Error = 0,
        /// The participant has been invited
        InvitationSent = 1,
        /// The participant has been onboarded
        Completed = 2,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ParticipantType {
    Individual = 0,
    Organization = 1,
}
#[doc = r" Generated client implementations."]
pub mod provider_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    pub struct ProviderClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl ProviderClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> ProviderClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        #[doc = "   rpc CreateOrganization(CreateOrganizationRequest) returns (CreateOrganizationResponse);"]
        pub async fn invite(
            &mut self,
            request: impl tonic::IntoRequest<super::InviteRequest>,
        ) -> Result<tonic::Response<super::InviteResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/trinsic.services.Provider/Invite");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn invite_with_workflow(
            &mut self,
            request: impl tonic::IntoRequest<super::InviteRequest>,
        ) -> Result<tonic::Response<super::InviteResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.Provider/InviteWithWorkflow",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn invitation_status(
            &mut self,
            request: impl tonic::IntoRequest<super::InvitationStatusRequest>,
        ) -> Result<tonic::Response<super::InvitationStatusResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/trinsic.services.Provider/InvitationStatus");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for ProviderClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for ProviderClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "ProviderClient {{ ... }}")
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateCredentialTemplateRequest {
    #[prost(message, optional, tag = "1")]
    pub template: ::core::option::Option<CredentialTemplate>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CreateCredentialTemplateResponse {
    #[prost(message, optional, tag = "1")]
    pub template: ::core::option::Option<CredentialTemplate>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetCredentialTemplateRequest {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetCredentialTemplateResponse {
    #[prost(string, tag = "1")]
    pub status: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListCredentialTemplatesRequest {
    #[prost(string, tag = "1")]
    pub query: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListCredentialTemplatesResponse {
    #[prost(message, repeated, tag = "1")]
    pub templates: ::prost::alloc::vec::Vec<CredentialTemplate>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteCredentialTemplateRequest {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeleteCredentialTemplateResponse {
    #[prost(string, tag = "1")]
    pub status: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CredentialTemplate {
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, repeated, tag = "4")]
    pub contexts: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(string, tag = "5")]
    pub schema: ::prost::alloc::string::String,
}
#[doc = r" Generated client implementations."]
pub mod credential_templates_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    pub struct CredentialTemplatesClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl CredentialTemplatesClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> CredentialTemplatesClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        pub async fn create(
            &mut self,
            request: impl tonic::IntoRequest<super::CreateCredentialTemplateRequest>,
        ) -> Result<tonic::Response<super::CreateCredentialTemplateResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.CredentialTemplates/Create",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn get(
            &mut self,
            request: impl tonic::IntoRequest<super::GetCredentialTemplateRequest>,
        ) -> Result<tonic::Response<super::GetCredentialTemplateResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/trinsic.services.CredentialTemplates/Get");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn list(
            &mut self,
            request: impl tonic::IntoRequest<super::ListCredentialTemplatesRequest>,
        ) -> Result<tonic::Response<super::ListCredentialTemplatesResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/trinsic.services.CredentialTemplates/List");
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn delete(
            &mut self,
            request: impl tonic::IntoRequest<super::DeleteCredentialTemplateRequest>,
        ) -> Result<tonic::Response<super::DeleteCredentialTemplateResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.CredentialTemplates/Delete",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for CredentialTemplatesClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for CredentialTemplatesClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "CredentialTemplatesClient {{ ... }}")
        }
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddTrustRegistryRequest {
    #[prost(string, tag = "1")]
    pub trust_registry: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub did_uri: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub description: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub website: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddTrustRegistryResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RemoveTrustRegistryRequest {
    #[prost(string, tag = "1")]
    pub trust_registry_uri: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RemoveTrustRegistryResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListTrustRegistriesRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListTrustRegistriesResponse {
    #[prost(message, repeated, tag = "1")]
    pub registries: ::prost::alloc::vec::Vec<TrustRegistry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TrustRegistry {
    #[prost(string, tag = "1")]
    pub trust_registry: ::prost::alloc::string::String,
    #[prost(string, tag = "3")]
    pub description: ::prost::alloc::string::String,
    #[prost(string, tag = "4")]
    pub website: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterAuthorityRequest {
    #[prost(enumeration = "AuthorityAction", repeated, tag = "20")]
    pub action: ::prost::alloc::vec::Vec<i32>,
    #[prost(oneof = "register_authority_request::Authority", tags = "1, 2")]
    pub authority: ::core::option::Option<register_authority_request::Authority>,
    #[prost(oneof = "register_authority_request::Template", tags = "10, 11")]
    pub template: ::core::option::Option<register_authority_request::Template>,
}
/// Nested message and enum types in `RegisterAuthorityRequest`.
pub mod register_authority_request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Authority {
        #[prost(string, tag = "1")]
        DidUri(::prost::alloc::string::String),
        #[prost(string, tag = "2")]
        X509Cert(::prost::alloc::string::String),
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Template {
        #[prost(string, tag = "10")]
        TemplateUri(::prost::alloc::string::String),
        #[prost(string, tag = "11")]
        ContextUri(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterAuthorityResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnregisterAuthorityRequest {
    #[prost(oneof = "unregister_authority_request::Authority", tags = "1, 2")]
    pub authority: ::core::option::Option<unregister_authority_request::Authority>,
    #[prost(oneof = "unregister_authority_request::Template", tags = "10, 11")]
    pub template: ::core::option::Option<unregister_authority_request::Template>,
}
/// Nested message and enum types in `UnregisterAuthorityRequest`.
pub mod unregister_authority_request {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Authority {
        #[prost(string, tag = "1")]
        DidUri(::prost::alloc::string::String),
        #[prost(string, tag = "2")]
        X509Cert(::prost::alloc::string::String),
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Template {
        #[prost(string, tag = "10")]
        TemplateUri(::prost::alloc::string::String),
        #[prost(string, tag = "11")]
        ContextUri(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnregisterAuthorityResponse {
    #[prost(enumeration = "ResponseStatus", tag = "1")]
    pub status: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckAuthorityRequest {
    #[prost(string, tag = "1")]
    pub authority: ::prost::alloc::string::String,
    /// Optional. If not specified, default EGF will be used
    #[prost(string, tag = "2")]
    pub trust_registry: ::prost::alloc::string::String,
    #[prost(enumeration = "AuthorityAction", tag = "3")]
    pub action: i32,
    /// Optional. If not specified, will return all authorized templates for this issuer
    /// under the specified EGF
    #[prost(string, tag = "4")]
    pub template_url: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CheckAuthorityResponse {
    #[prost(string, tag = "1")]
    pub authority: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "2")]
    pub result: ::prost::alloc::vec::Vec<AuthorityEntry>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AuthorityEntry {
    #[prost(string, tag = "1")]
    pub template_url: ::prost::alloc::string::String,
    #[prost(enumeration = "AuthorityAction", tag = "2")]
    pub action: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AuthorityAction {
    Issue = 0,
    Verify = 1,
}
#[doc = r" Generated client implementations."]
pub mod trust_registry_service_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    pub struct TrustRegistryServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl TrustRegistryServiceClient<tonic::transport::Channel> {
        #[doc = r" Attempt to create a new client by connecting to a given endpoint."]
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> TrustRegistryServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        #[doc = " Adds a trust registry defintion to the ecosystem"]
        pub async fn add_trust_registry(
            &mut self,
            request: impl tonic::IntoRequest<super::AddTrustRegistryRequest>,
        ) -> Result<tonic::Response<super::AddTrustRegistryResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.TrustRegistryService/AddTrustRegistry",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn remove_trust_registry(
            &mut self,
            request: impl tonic::IntoRequest<super::RemoveTrustRegistryRequest>,
        ) -> Result<tonic::Response<super::RemoveTrustRegistryResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.TrustRegistryService/RemoveTrustRegistry",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn list_trust_registries(
            &mut self,
            request: impl tonic::IntoRequest<super::ListTrustRegistriesRequest>,
        ) -> Result<tonic::Response<super::ListTrustRegistriesResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.TrustRegistryService/ListTrustRegistries",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Registers an authoritative issuer with a credential template"]
        pub async fn register_authority(
            &mut self,
            request: impl tonic::IntoRequest<super::RegisterAuthorityRequest>,
        ) -> Result<tonic::Response<super::RegisterAuthorityResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.TrustRegistryService/RegisterAuthority",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        #[doc = " Removes an authoritative issuer with a credential template from the trust registry"]
        pub async fn unregister_authority(
            &mut self,
            request: impl tonic::IntoRequest<super::UnregisterAuthorityRequest>,
        ) -> Result<tonic::Response<super::UnregisterAuthorityResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.TrustRegistryService/UnregisterAuthority",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        pub async fn check_authority(
            &mut self,
            request: impl tonic::IntoRequest<super::CheckAuthorityRequest>,
        ) -> Result<tonic::Response<super::CheckAuthorityResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/trinsic.services.TrustRegistryService/CheckAuthority",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for TrustRegistryServiceClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for TrustRegistryServiceClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TrustRegistryServiceClient {{ ... }}")
        }
    }
}
