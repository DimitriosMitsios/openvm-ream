use eyre::Result;
use openvm_build::GuestOptions;
use std::path::{PathBuf};
use std::{env, sync::Arc};
use openvm_sdk::{config::{SdkVmConfig, AppConfig}, StdIn, Sdk};
use openvm_circuit::openvm_stark_sdk::{config::FriParameters};
use ream_lib::file::ssz_from_file;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .build();

    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../guest");

    // Build the ELF file

    let sdk = Sdk::new();
    let guest_opts = GuestOptions::default();
    let target_path = "../guest";
    let elf = sdk.build(
        guest_opts,
        &vm_config,
        target_path,
        &Default::default(),
        None,
    )?;

    // Transpile the ELF into VmExe

    let exe = sdk.transpile(elf, vm_config.transpiler())?;

    // Input to stdin
    let pre_state_path = &std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
            .join("../assets/one_basic_attestation/pre.ssz_snappy");

    let attestation_path: &PathBuf = &std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
            .join("../assets/one_basic_attestation/attestation.ssz_snappy");

    let mut stdin = StdIn::default();
    let pre_state_bytes: Vec<u8> =ssz_from_file(&pre_state_path); // pre_state_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let attestation_bytes: Vec<u8> = ssz_from_file(&attestation_path); // attestation_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let pre_state_len_bytes: Vec<u8> = pre_state_bytes.len().to_be_bytes().to_vec();

    stdin.write_bytes(&pre_state_len_bytes);
    stdin.write_bytes(&pre_state_bytes);
    stdin.write_bytes(&attestation_bytes);


    // // Run the benchmark

    let output = sdk.execute(exe.clone(), vm_config.clone(), stdin.clone());

    println!("public values output: {:?}", output);

    // ANCHOR: proof_generation
    // 6. Set app configuration
    let app_log_blowup = 2;
    let app_fri_params = FriParameters::standard_with_100_bits_conjectured_security(app_log_blowup);
    let app_config = AppConfig::new(app_fri_params, vm_config);

    // 7. Commit the exe
    println!("Committing app exe -- START");
    let app_committed_exe = sdk.commit_app_exe(app_fri_params, exe)?;
    println!("Committing app exe -- END");

    // 8. Generate an AppProvingKey
    println!("Generating AppProvingKey -- START");
    let app_pk = Arc::new(sdk.app_keygen(app_config)?);
    println!("Generating AppProvingKey -- END");

    // 9a. Generate a proof
    // println!("Generating proof -- START");
    // let proof = sdk.generate_app_proof(app_pk.clone(), app_committed_exe.clone(), stdin.clone())?;
    // println!("Generating proof -- END");

    // // 10. Verify your program
    // println!("Verifying proof -- START");
    // let app_vk = app_pk.get_app_vk();
    // sdk.verify_app_proof(&app_vk, &proof)?;
    // println!("Verifying proof -- END");

    Ok(())
}