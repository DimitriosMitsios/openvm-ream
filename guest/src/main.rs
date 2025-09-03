// src/main.rs
use openvm::io::{read_vec, read};
use ream_consensus::{attestation::Attestation, electra::beacon_state::BeaconState};
use ream_lib::{ssz::from_ssz_bytes};

// fn deserialize<T: ssz::Decode>(ssz_bytes: &[u8]) -> T {
//     // eprintln!("{}-{}:{}: {}", "deserialize", std::any::type_name::<T>(), "start", env::cycle_count());
//     let deserialized = from_ssz_bytes(&ssz_bytes).unwrap();
//     // eprintln!("{}-{}:{}: {}", "deserialize", std::any::type_name::<T>(), "end", env::cycle_count());

//     deserialized
// }

pub fn main() {

    let bytes: Vec<u8> = read_vec();
    let arr: [u8;8] = bytes.try_into().unwrap();
    let pre_state_len = u64::from_le_bytes(arr) as usize;
    let mut pre_state_ssz_bytes: Vec<u8> = vec![0u8; pre_state_len];
    pre_state_ssz_bytes = read_vec();
    let mut pre_state: BeaconState = from_ssz_bytes(&pre_state_ssz_bytes).unwrap();
    let mut attestation_bytes = Vec::new();
    attestation_bytes = read_vec();
    let attestation: Attestation = from_ssz_bytes(&attestation_bytes).unwrap();
    let _ = pre_state.process_attestation(&attestation);

    let mut hash = Sha256::new();
    hash.update(&pre_state);
    let digest: [u8, 32] = hash.finalize().into();
    openvm::io::reveal_bytes(&digest);

    // hash.update(pre_state_ssz_bytes.as_slice());
    // let new_state_root = hash.finalize();
    // println!("new_state_root: {}", new_state_root);
}