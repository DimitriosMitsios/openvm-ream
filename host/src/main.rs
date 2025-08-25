use clap::Parser;
use eyre::Result;
use openvm_build::GuestOptions;
use std::path::{self, Path, PathBuf};
use std::{fs, env};
use openvm::platform::memory::MEM_SIZE;
use openvm_benchmarks_prove::util::BenchmarkCli;
use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_rv32im_circuit::Rv32ImConfig;
use openvm_rv32im_transpiler::{
    Rv32ITranspilerExtension, Rv32IoTranspilerExtension, Rv32MTranspilerExtension,
};
use openvm_sdk::{config::{SdkVmConfig, AppConfig}, StdIn, Sdk, F};
use openvm_stark_sdk::{bench::run_with_metric_collection, p3_baby_bear::BabyBear, config::FriParameters};
use openvm_transpiler::{transpiler::Transpiler, FromElf, elf::Elf};

use ream_consensus::{attestation::{self, Attestation}, electra::beacon_state::BeaconState};

// Dependencies for testing deserialization
use std::{
    collections::{HashMap, VecDeque},
};
use serde::{Deserialize, Serialize};
use openvm_stark_backend::p3_field::FieldAlgebra;
use p3_monty_31::MontyField31;
use p3_baby_bear::BabyBearParameters;
use ream_lib::file::ssz_from_file;
fn read_elf() -> Result <(), Box<dyn std::error::Error>> {
    let elf_bytes = fs::read("../guest")?;
    let elf = Elf::decode(&elf_bytes, MEM_SIZE as u32)?;
    Ok(())
}

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

    let pre_state: BeaconState = utils::read_file(
        &std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
            .join("../assets/one_basic_attestation/pre.ssz_snappy"),
    );
    let attestation: Attestation = utils::read_file(
        &std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
            .join("../assets/one_basic_attestation/attestation.ssz_snappy"),
    );

    let mut stdin = StdIn::default();
    // let pre_state_words = openvm::serde::to_vec(&pre_state).unwrap();
    let pre_state_bytes: Vec<u8> =ssz_from_file(&pre_state_path); // pre_state_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    // let attestation_words = openvm::serde::to_vec(&attestation).unwrap();
    let attestation_bytes: Vec<u8> = ssz_from_file(&attestation_path); // attestation_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let pre_state_len_bytes: Vec<u8> = pre_state_bytes.len().to_be_bytes().to_vec();
    // let pre_field_data: Vec<MontyField31<BabyBearParameters>> = pre_bytes.iter().map(|b| F::from_canonical_u8(*b)).collect();
    // let stdin.push_back(pre_field_data);

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


    Ok(())
}