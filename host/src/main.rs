use clap::Parser;
use tracing::info;
use eyre::Result;
use openvm_build::GuestOptions;
use std::path::PathBuf;
use openvm_sdk::{StdIn, Sdk};
use openvm_sdk::prover::verify_app_proof;
use ream_lib::{file::ssz_from_file, input::OperationInput, ssz::{from_ssz_bytes, }};
use ream_consensus::electra::beacon_state::BeaconState;
use tree_hash::{Hash256, TreeHash};

// Dependencies for setup_logs
mod cli;
use cli::{fork::Fork, operation::{Operation, OperationHandler}};

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
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

    /// Generate cryptographic proofs for the execution
    #[clap(long, default_value_t = false)]
    generate_proof: bool,

    #[clap(long)]
    excluded_cases: Vec<String>,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_log();

    let (fork, operation, excluded_cases, compare_specs, compare_recompute, generate_proof) = parse_args();

    match operation {
        Operation::Block { operation: block_op } => {
            run_operation(&fork, &block_op, &excluded_cases, compare_specs, compare_recompute, generate_proof)?;
        }
        Operation::Epoch { operation: epoch_op } => {
            run_operation(&fork, &epoch_op, &excluded_cases, compare_specs, compare_recompute, generate_proof)?;
        }
    }

    Ok(())
}

fn run_operation<T: OperationHandler>(
    fork: &Fork,
    operation: &T,
    excluded_cases: &[String],
    compare_specs: bool,
    compare_recompute: bool,
    generate_proof: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (base_dir, test_cases) = operation.load_test_cases(fork);

    for test_case in test_cases {
        if excluded_cases.contains(&test_case) {
            info!("Skipping test case: {test_case}");
            continue;
        }

        info!("[{}] Test case: {test_case}", operation);

        // Build the ELF file
        let sdk = Sdk::standard();
        let guest_opts = GuestOptions::default();
        let target_path = "../guest";
        let elf = sdk.build(
            guest_opts,
            target_path,
            &None,
            None,
        )?;

        // Prepare input
        let case_dir = base_dir.join(&test_case);
        let input = operation.prepare_input(&case_dir);
        let pre_state_ssz_bytes: Vec<u8> = ssz_from_file(&case_dir.join("pre.ssz_snappy"));
        let pre_state: BeaconState = from_ssz_bytes(&pre_state_ssz_bytes).unwrap();

        let mut stdin = StdIn::default();
        stdin.write(&input);
        stdin.write(&pre_state);

        let output = sdk.execute(elf.clone(), stdin.clone())?;

        // Compare proofs against references (consensus-spec-tests or recompute on host)
        if output.len() != 32 {
            return Err("unexpected public values length".into());
        }

        let new_state_root_hash: [u8; 32] = output
            .try_into()
            .expect("checked length; conversion can't fail");

        // Compare state root hash to specs
        if compare_specs {
            info!("Comparing the root against consensus-spec-tests post_state");
            assert_state_root_matches_specs(&new_state_root_hash.into(), &pre_state_ssz_bytes, &case_dir);
        }

        if compare_recompute {
            info!("Comparing the root by recomputing on host");
            assert_state_root_matches_recompute(&new_state_root_hash.into(), &pre_state_ssz_bytes, &input);
        }

        // Generate cryptographic proof if requested
        if generate_proof {
            info!("Generating cryptographic proof for test case: {test_case}");
            let mut prover = sdk.app_prover(elf.clone())?.with_program_name(&format!("{}_{}", operation, test_case));
            let proof = prover.prove(stdin.clone())?;
            info!("Proof generated successfully for test case: {test_case}");

            // Generate app verification keys and verify the proof
            let (_app_pk, app_vk) = sdk.app_keygen();
            match verify_app_proof(&app_vk, &proof) {
                Ok(_) => info!("Proof verified successfully for test case: {test_case}"),
                Err(e) => info!("Proof verification failed for test case {test_case}: {}", e),
            }
        }
    }

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

fn parse_args() -> (Fork, Operation, Vec<String>, bool, bool, bool) {
    let args = Args::parse();

    (
        args.fork.fork,
        args.operation.operation,
        args.excluded_cases,
        args.compare_specs,
        args.compare_recompute,
        args.generate_proof,
    )
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
        OperationInput::Block(wrapper) => {
            let _ = wrapper.process_operation(&mut state);
        }
        OperationInput::Epoch(wrapper) => {
            let _ = wrapper.process_operation(&mut state);
        }
    }

    let recomputed_state_root = state.tree_hash_root();

    assert_eq!(*new_state_root, recomputed_state_root);
    info!("Execution is correct! State roots match host's recomputed state root.");
}

