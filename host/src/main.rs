use clap::Parser;
use eyre::Result;
use openvm_benchmarks_prove::util::BenchmarkCli;
use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_rv32im_circuit::Rv32ImConfig;
use openvm_rv32im_transpiler::{
    Rv32ITranspilerExtension, Rv32IoTranspilerExtension, Rv32MTranspilerExtension,
};
use openvm_sdk::StdIn;
use openvm_stark_sdk::{bench::run_with_metric_collection, p3_baby_bear::BabyBear};
use openvm_transpiler::{transpiler::Transpiler, FromElf};

use ream_consensus::{attestation::Attestation, electra::beacon_state::BeaconState};
use ream_lib::{file::ssz_from_file, input::OperationInput, ssz::from_ssz_bytes};

fn main() -> Result<()> {
    let args = BenchmarkCli::parse();

    let config = Rv32ImConfig::default();
    let elf = args.build_bench_program("attestation", &config, None)?;
    let exe = VmExe::from_elf(
        elf,
        Transpiler::<BabyBear>::default()
            .with_extension(Rv32ITranspilerExtension)
            .with_extension(Rv32MTranspilerExtension)
            .with_extension(Rv32IoTranspilerExtension),
    )?;

    run_with_metric_collection("OUTPUT_PATH", || -> Result<()> {
        let pre_state_ssz_bytes: Vec<u8> = ssz_from_file("~/Documents/Projects/epf6/openvm-ream/assets/one_basic_attestation/pre.ssz_snappy");
        let pre_state: BeaconState = from_ssz_bytes(&pre_state_ssz_bytes).unwrap();
        let attestation: Attestation = OperationInput::Attestation(ssz_from_file(input_path));
        let mut stdin = StdIn::default();
        stdin.write(&pre_state);
        stdin.write(&attestation);
        args.bench_from_exe("fibonacci_program", config, exe, stdin);
    })
}