use clap::Parser;
use tracing::{error, info};
use eyre::Result;
use openvm_build::GuestOptions;
use std::path::{PathBuf};
use std::{env, sync::Arc};
use openvm_sdk::{config::{SdkVmConfig, AppConfig}, StdIn, Sdk};
use openvm_circuit::openvm_stark_sdk::{config::FriParameters};
use ream_lib::{file::ssz_from_file, input::OperationInput, ssz::from_ssz_bytes};
use ream_consensus::{
    bls_to_execution_change::SignedBLSToExecutionChange,
    deposit::Deposit,
    proposer_slashing::ProposerSlashing,
    sync_aggregate::SyncAggregate,
    voluntary_exit::SignedVoluntaryExit,
    electra::{beacon_block::BeaconBlock, beacon_state::BeaconState, execution_payload::ExecutionPayload},
    attestation::Attestation, attester_slashing::AttesterSlashing
};
use tree_hash::{Hash256, TreeHash};

// Dependencies for setup_logs
mod cli;
use cli::{fork::Fork, operation::OperationName};

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]struct Args {
    /// Argument for STFs
    #[clap(flatten)]
    fork: cli::fork::ForkArgs,

    #[clap(flatten)]
    operation: cli::operation::OperationArgs,

    /// Verify the correctness of the state root by comparing against consensus-spec-tests' post_state
    #[clap(long, default_value_t = false)]
    compare_specs: bool,

    /// Verify the correctness of the state root by recomputing on the host
    #[clap(long, default_value_t = true)]
    compare_recompute: bool,

    #[clap(long)]
    excluded_cases: Vec<String>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_log();

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
fn setup_log() {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }

    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
}

fn parse_args() -> (Fork, OperationName, Vec<String>, bool, bool) {
    let args = Args::parse();

    (
        args.fork.fork,
        args.operation.operation_name,
        args.excluded_cases,
        args.compare_specs,
        args.compare_recompute,
    )
}

fn prepare_input(case_dir: &PathBuf, operation_name: &OperationName) -> OperationInput {
    let input_path = &case_dir.join(format!("{}.ssz_snappy", operation_name.to_input_name()));

    match operation_name {
        OperationName::Attestation => OperationInput::Attestation(ssz_from_file(input_path)),
        OperationName::AttesterSlashing => {
            OperationInput::AttesterSlashing(ssz_from_file(input_path))
        }
        OperationName::BlockHeader => OperationInput::BeaconBlock(ssz_from_file(input_path)),
        OperationName::BLSToExecutionChange => {
            OperationInput::SignedBLSToExecutionChange(ssz_from_file(input_path))
        }
        OperationName::Deposit => OperationInput::Deposit(ssz_from_file(input_path)),
        OperationName::ExecutionPayload => {
            OperationInput::BeaconBlockBody(ssz_from_file(input_path))
        }
        OperationName::ProposerSlashing => {
            OperationInput::ProposerSlashing(ssz_from_file(input_path))
        }
        OperationName::SyncAggregate => OperationInput::SyncAggregate(ssz_from_file(input_path)),
        OperationName::VoluntaryExit => {
            OperationInput::SignedVoluntaryExit(ssz_from_file(input_path))
        }
        OperationName::Withdrawals => OperationInput::ExecutionPayload(ssz_from_file(input_path)),
    }
}

fn load_test_cases(fork: &Fork, operation_name: &OperationName) -> (PathBuf, Vec<String>) {

    // These assets are from consensus-specs repo.
    let test_case_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("mainnet")
        .join("tests")
        .join("mainnet");

    if !std::path::Path::new(&test_case_dir).exists() {
        error!("Error: You must first download test data via `make download`");
        std::process::exit(1);
    }

    let base_dir = test_case_dir
        .join(format!("{}", fork))
        .join("operations")
        .join(format!("{}", operation_name))
        .join("pyspec_tests");

    let test_cases = ream_lib::file::get_test_cases(&base_dir);

    (base_dir, test_cases)
}

fn assert_state_root_matches_specs(
    new_state_root: &Hash256,
    pre_state_ssz_bytes: &[u8],
    case_dir: &PathBuf,
) {
    let post_state_opt: Option<BeaconState> = {
        if case_dir.join("post.ssz_snappy").exists() {
            let ssz_bytes: Vec<u8> = ssz_from_file(&case_dir.join("post.ssz_snappy"));
            Some(from_ssz_bytes(&ssz_bytes).unwrap())
        } else {
            None
        }
    };

    match post_state_opt {
        // If the specs provide post_state, compare the computed root against post_state's root
        Some(post_state) => {
            info!("post_state provided. The state root should be mutated.");
            assert_eq!(*new_state_root, post_state.tree_hash_root());
            info!("Execution is correct! State mutated and the roots match.");
        }
        // If the specs does not contain a post_state, compare the computed root against pre_state's root
        None => {
            info!("post_state not provided. The state root should not be mutated.");
            let pre_state: BeaconState = from_ssz_bytes(&pre_state_ssz_bytes).unwrap();
            assert_eq!(*new_state_root, pre_state.tree_hash_root());
            info!("Execution is correct! State should not be mutated and the roots match.");
        }
    }
}

fn assert_state_root_matches_recompute(
    new_state_root: &Hash256,
    pre_state_ssz_bytes: &[u8],
    input: &OperationInput,
) {
    let mut state: BeaconState = from_ssz_bytes(&pre_state_ssz_bytes).unwrap();

    match input {
        OperationInput::Attestation(ssz_bytes) => {
            let attestation: Attestation = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = state.process_attestation(&attestation);
        }
        OperationInput::AttesterSlashing(ssz_bytes) => {
            let attester_slashing: AttesterSlashing = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = state.process_attester_slashing(&attester_slashing);
        }
        OperationInput::BeaconBlock(ssz_bytes) => {
            let block: BeaconBlock = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = state.process_block_header(&block);
        }
        OperationInput::SignedBLSToExecutionChange(ssz_bytes) => {
            let bls_change: SignedBLSToExecutionChange = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = state.process_bls_to_execution_change(&bls_change);
        }
        OperationInput::Deposit(ssz_bytes) => {
            let deposit: Deposit = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = state.process_deposit(&deposit);
        }
        OperationInput::BeaconBlockBody(_ssz_bytes) => {
            panic!("Not implemented");
            // let block_body: BeaconBlockBody = from_ssz_bytes(&ssz_bytes).unwrap();
            // let _ = state.process_execution_payload(&block_body);
        }
        OperationInput::ProposerSlashing(ssz_bytes) => {
            let proposer_slashing: ProposerSlashing = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = state.process_proposer_slashing(&proposer_slashing);
        }
        OperationInput::SyncAggregate(ssz_bytes) => {
            let sync_aggregate: SyncAggregate = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = state.process_sync_aggregate(&sync_aggregate);
        }
        OperationInput::SignedVoluntaryExit(ssz_bytes) => {
            let voluntary_exit: SignedVoluntaryExit = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = state.process_voluntary_exit(&voluntary_exit);
        }
        OperationInput::ExecutionPayload(ssz_bytes) => {
            let execution_payload: ExecutionPayload = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = state.process_withdrawals(&execution_payload);
        }
    }

    let recomputed_state_root = state.tree_hash_root();

    println!("recomputed_state_root: {}", recomputed_state_root);
    println!("new_state_root: {}", new_state_root);

    assert_eq!(*new_state_root, recomputed_state_root);
    info!("Execution is correct! State roots match host's recomputed state root.");
}