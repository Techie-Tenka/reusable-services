fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = "src/integration/grpc/out";

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(out_dir)
        .compile_protos(
            &[
                "proto/acl/acl.proto",
                "proto/email/email.proto",
                "proto/files/files.proto",
                "proto/payments/payments.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}

// sorry I just wanna trigger a build!
