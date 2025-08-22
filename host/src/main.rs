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
use openvm_sdk::{config::SdkVmConfig, StdIn, Sdk};
use openvm_stark_sdk::{bench::run_with_metric_collection, p3_baby_bear::BabyBear};
use openvm_transpiler::{transpiler::Transpiler, FromElf, elf::Elf};

use ream_consensus::{attestation::{self, Attestation}, electra::beacon_state::BeaconState};
use ream_lib::{file::ssz_from_file, input::OperationInput, ssz::from_ssz_bytes};

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

    let pre_state: BeaconState = utils::read_file(
        &std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
            .join("../assets/one_basic_attestation/pre.ssz_snappy"),
    );
    let attestation: Attestation = utils::read_file(
        &std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
            .join("../assets/one_basic_attestation/attestation.ssz_snappy"),
    );
    let mut stdin = StdIn::default();

    stdin.write(&pre_state);
    stdin.write(&attestation);


    // Run the benchmark

    let output = sdk.execute(exe.clone(), vm_config.clone(), stdin.clone());

    println!("public values output: {:?}", output);
    Ok(())
}