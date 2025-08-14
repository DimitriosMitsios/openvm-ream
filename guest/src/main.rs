// src/main.rs
use openvm::io::read;
use ream_consensus::{attestation::Attestation, deneb::beacon_state::BeaconState};

pub fn main() {
    let mut pre_state = read::<BeaconState>();
    let attestation = read::<Attestation>();
    let _ = pre_state.process_attestation(&attestation);
}