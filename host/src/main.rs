// THE FOLLOWING CODE IS A MIXTURE OF JUN'S ERE-REAM AND OPENVM SDK EXAMPLESS sdk_app.rs. Formatting of the input is borrowed from ream's examples.

// ANCHOR: dependencies
use std::{env, fs, sync::Arc};

use ream_consensus::{attestation::Attestation, electra::beacon_state::BeaconState};

use eyre::Result;
use openvm::platform::memory::MEM_SIZE;
use openvm_build::GuestOptions;
use openvm_sdk::{
    Sdk, StdIn,
    config::{AppConfig, SdkVmConfig},
    prover::AppProver,
};
use openvm_stark_sdk::config::{FriParameters, baby_bear_poseidon2::BabyBearPoseidon2Engine};
use openvm_transpiler::elf::Elf;
use serde::{Deserialize, Serialize};

// ANCHOR_END: dependencies

#[allow(dead_code, unused_variables)]
fn read_elf() -> Result<(), Box<dyn std::error::Error>> {
    // ANCHOR: read_elf
    // 2b. Load the ELF from a file
    let elf_bytes = fs::read("your_path_to_elf")?; // I don't know the elf path
    let elf = Elf::decode(&elf_bytes, MEM_SIZE as u32)?;
    // ANCHOR_END: read_elf
    Ok(())
}
fn main() -> eyre::Result<()> {
    // ANCHOR: vm_config
    let vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .build();
    // ANCHOR_END: vm_config

    /// to import example guest code in crate replace `target_path` for:
    /// ```
    /// use std::path::PathBuf;
    ///
    /// let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    /// path.push("guest/fib");
    /// let target_path = path.to_str().unwrap();
    /// ```
    // ANCHOR: build
    // 1. Build the VmConfig with the extensions needed.
    let sdk = Sdk::new();

    // 2a. Build the ELF with guest options and a target filter.
    let target_path = "../..";
    let elf = sdk.build(GuestOptions::default(), target_path, &Default::default())?;
    // ANCHOR_END: build

    // Set up zkVM instance by cargo feature flags.
    // let zkvm = zkvms::new_zkvm(ProverResourceType::Cpu)?;

    // Read inputs from files.
    let pre_state: BeaconState = utils::read_file(
        &std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
            .join("../../assets/one_basic_attestation/pre.ssz_snappy"),
    );
    let attestation: Attestation = utils::read_file(
        &std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
            .join("../../assets/one_basic_attestation/attestation.ssz_snappy"),
    );

    // ANCHOR: transpilation
    // 3. Transpile the ELF into a VmExe
    let exe = sdk.transpile(elf, vm_config.transpiler())?;
    // ANCHOR_END: transpilation

    // ANCHOR: execution
    // 4. Format your input into StdIn
    // TODO

    Ok(())
}
