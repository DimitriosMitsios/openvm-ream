// src/main.rs
use openvm::io::{read};
use ream_lib::{input::{OperationInput}, ssz::from_ssz_bytes};
use tree_hash::{TreeHash};
use ream_consensus::{
    bls_to_execution_change::SignedBLSToExecutionChange,
    deposit::Deposit,
    proposer_slashing::ProposerSlashing,
    sync_aggregate::SyncAggregate,
    voluntary_exit::SignedVoluntaryExit,
    electra::{beacon_block::BeaconBlock, beacon_state::BeaconState, execution_payload::ExecutionPayload},
    attestation::Attestation, attester_slashing::AttesterSlashing
};

// Dependencies for hashing
pub fn main() {

    let input: OperationInput = read();
    let mut pre_state: BeaconState = read();

    match input {
        OperationInput::Attestation(ssz_bytes) => {
            let attestation: Attestation = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = pre_state.process_attestation(&attestation);
        }
        OperationInput::AttesterSlashing(ssz_bytes) => {
            let attester_slashing: AttesterSlashing = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = pre_state.process_attester_slashing(&attester_slashing);
        }
        OperationInput::BeaconBlock(ssz_bytes) => {
            let block: BeaconBlock = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = pre_state.process_block_header(&block);
        }
        OperationInput::SignedBLSToExecutionChange(ssz_bytes) => {
            let bls_change: SignedBLSToExecutionChange = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = pre_state.process_bls_to_execution_change(&bls_change);
        }
        OperationInput::Deposit(ssz_bytes) => {
            let deposit: Deposit = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = pre_state.process_deposit(&deposit);
        }
        OperationInput::BeaconBlockBody(_ssz_bytes) => {
            panic!("Not implemented");
            // let block_body: BeaconBlockBody = from_ssz_bytes(&ssz_bytes).unwrap();
            // let _ = pre_state.process_execution_payload(&block_body);
        }
        OperationInput::ProposerSlashing(ssz_bytes) => {
            let proposer_slashing: ProposerSlashing = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = pre_state.process_proposer_slashing(&proposer_slashing);
        }
        OperationInput::SyncAggregate(ssz_bytes) => {
            let sync_aggregate: SyncAggregate = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = pre_state.process_sync_aggregate(&sync_aggregate);
        }
        OperationInput::SignedVoluntaryExit(ssz_bytes) => {
            let voluntary_exit: SignedVoluntaryExit = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = pre_state.process_voluntary_exit(&voluntary_exit);
        }
        OperationInput::ExecutionPayload(ssz_bytes) => {
            let execution_payload: ExecutionPayload = from_ssz_bytes(&ssz_bytes).unwrap();
            let _ = pre_state.process_withdrawals(&execution_payload);
        }
    }

    // Computing the tree_hash_root of the updated pre_state
    let digest = pre_state.tree_hash_root();

    openvm::io::reveal_bytes32(*digest);

}