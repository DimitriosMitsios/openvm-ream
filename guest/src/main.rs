// src/main.rs
use openvm::io::read;
use ream_lib::input::OperationInput;
use tree_hash::TreeHash;
use ream_consensus::electra::beacon_state::BeaconState;

// Dependencies for hashing
pub fn main() {

    let input: OperationInput = read();
    let mut pre_state: BeaconState = read();

    // Process the operation on the beacon state using the centralized process method
    input.process(&mut pre_state);

    // Computing the tree_hash_root of the updated pre_state
    let digest = pre_state.tree_hash_root();

    openvm::io::reveal_bytes32(*digest);

}