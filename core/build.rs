fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../shared/netspectre.proto");
    tonic_prost_build::compile_protos("../shared/netspectre.proto")?;
    Ok(())
}
