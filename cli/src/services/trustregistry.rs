use tonic::transport::Channel;
use trinsic::{trust_registry_client::TrustRegistryClient, SearchRegistryRequest, *};

use crate::parser::trustregistry::*;

use super::config::{Config, Error};

pub(crate) fn execute(args: &Command, config: &Config) -> Result<(), Error> {
    match args {
        Command::Search(args) => Ok(search(args, config)),
        Command::RegisterIssuer(args) => Ok(register_issuer(args, config)),
        Command::RegisterVerifier(args) => Ok(register_verifier(args, config)),
        Command::UnregisterIssuer(args) => Ok(unregister_issuer(args, config)),
        Command::UnregisterVerifier(args) => Ok(unregister_verifier(args, config)),
        Command::CheckIssuer(args) => Ok(check_issuer(args, config)),
        Command::CheckVerifier(args) => Ok(check_verifier(args, config)),
    }
}

#[tokio::main]
async fn search(args: &SearchArgs, config: &Config) {
    let query = args
        .query
        .as_ref()
        .map_or("SELECT * FROM c".to_string(), |q| q.to_owned());

    let mut client = grpc_client_with_auth!(TrustRegistryClient<Channel>, config.to_owned());

    let request = tonic::Request::new(SearchRegistryRequest {
        query: query.clone(),
        ..Default::default()
    });

    let response = client
        .search_registry(request)
        .await
        .expect("search registry command failed")
        .into_inner();

    println!("{}", serde_json::to_string_pretty(&response.items).unwrap());
}

#[tokio::main]
async fn register_issuer(args: &RegistrationArgs, config: &Config) {
    let mut client = grpc_client_with_auth!(TrustRegistryClient<Channel>, config.to_owned());

    let request = tonic::Request::new(RegisterIssuerRequest {
        authority: Some(register_issuer_request::Authority::DidUri(
            args.did_uri.clone().unwrap(),
        )),
        credential_type_uri: args.type_uri.clone().expect("credential type is required"),
        governance_framework_uri: args
            .governance_framework_uri
            .clone()
            .expect("governance framework is required"),
        ..Default::default()
    });

    let response = client
        .register_issuer(request)
        .await
        .expect("register issuer command failed")
        .into_inner();

    println!(
        "{}",
        serde_json::to_string_pretty(&response.response_data).unwrap()
    );
}

#[tokio::main]
async fn check_issuer(args: &RegistrationArgs, config: &Config) {
    let mut client = grpc_client_with_auth!(TrustRegistryClient<Channel>, config.to_owned());

    let request = tonic::Request::new(CheckIssuerStatusRequest {
        member: Some(check_issuer_status_request::Member::DidUri(
            args.did_uri.clone().unwrap(),
        )),
        credential_type_uri: args.type_uri.clone().expect("credential type is required"),
        governance_framework_uri: args
            .governance_framework_uri
            .clone()
            .expect("governance framework is required"),
        ..Default::default()
    });

    let response = client
        .check_issuer_status(request)
        .await
        .expect("check issuer command failed")
        .into_inner();

    println!(
        "{}",
        serde_json::to_string_pretty(&response.status).unwrap()
    );
}

#[tokio::main]
async fn check_verifier(args: &RegistrationArgs, config: &Config) {
    let mut client = grpc_client_with_auth!(TrustRegistryClient<Channel>, config.to_owned());

    let request = tonic::Request::new(CheckVerifierStatusRequest {
        member: Some(check_verifier_status_request::Member::DidUri(
            args.did_uri.clone().unwrap(),
        )),
        presentation_type_uri: args
            .type_uri
            .clone()
            .expect("presentation type is required"),
        governance_framework_uri: args
            .governance_framework_uri
            .clone()
            .expect("governance framework is required"),
        ..Default::default()
    });

    let response = client
        .check_verifier_status(request)
        .await
        .expect("check verifier command failed")
        .into_inner();

    println!(
        "{}",
        serde_json::to_string_pretty(&response.status).unwrap()
    );
}

fn unregister_issuer(args: &RegistrationArgs, config: &Config) {
    todo!()
}

#[tokio::main]
async fn register_verifier(args: &RegistrationArgs, config: &Config) {
    let mut client = grpc_client_with_auth!(TrustRegistryClient<Channel>, config.to_owned());

    let request = tonic::Request::new(RegisterVerifierRequest {
        authority: Some(register_verifier_request::Authority::DidUri(
            args.did_uri.clone().unwrap(),
        )),
        presentation_type_uri: args
            .type_uri
            .clone()
            .expect("presentation type is required"),
        governance_framework_uri: args
            .governance_framework_uri
            .clone()
            .expect("governance framework is required"),
        ..Default::default()
    });

    let response = client
        .register_verifier(request)
        .await
        .expect("register verifier command failed")
        .into_inner();

    println!(
        "{}",
        serde_json::to_string_pretty(&response.response_data).unwrap()
    );
}

fn unregister_verifier(args: &RegistrationArgs, config: &Config) {
    todo!()
}
