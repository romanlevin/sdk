use std::fs::{copy, remove_file};

fn main() {
    let config = tonic_build::configure()
        .build_server(false)
        .out_dir("./src/proto");

    let mut prost_config = prost_build::Config::new();
    prost_config.compile_well_known_types();
    //.type_attribute(".", "#[derive(::serde::Serialize, ::serde::Deserialize)]");

    config
        .compile_with_config(
            prost_config,
            &[
                "../proto/proto/pbmse/pbmse.proto",
                "../proto/proto/greet.proto",
                "../proto/proto/AuthService.proto",
                "../proto/proto/CoreService.proto",
                "../proto/proto/IssuerService.proto",
                "../proto/proto/WalletService.proto",
            ],
            &["../proto/proto"],
        )
        .unwrap();

    copy(
        "./src/proto/google.protobuf.rs",
        "./src/proto/google_protobuf.rs",
    )
    .unwrap();
    copy(
        "./src/proto/trinsic.services.rs",
        "./src/proto/trinsic_services.rs",
    )
    .unwrap();
    remove_file("./src/proto/google.protobuf.rs").unwrap();
    remove_file("./src/proto/trinsic.services.rs").unwrap();
}
