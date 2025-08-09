use std::path::Path;

use snap::raw::Decoder;

pub fn read_file<T: ssz::Decode>(path: &Path) -> T {
    let raw_bytes =
        std::fs::read(path).unwrap_or_else(|e| panic!("Could not read file: {:?}: {}", path, e));
    let ssz_bytes = decode_snappy(&raw_bytes).unwrap_or_else(|e| {
        panic!("Could not decode snappy {:?}: {}", path, e);
    });
    to_ssz(&ssz_bytes).unwrap_or_else(|| {
        panic!("Could not decode ssz {:?}", path);
    })
}

pub fn decode_snappy(raw_bytes: &[u8]) -> Result<Vec<u8>, snap::Error> {
    let mut decoder = Decoder::new();
    decoder.decompress_vec(raw_bytes)
}

pub fn to_ssz<T: ssz::Decode>(ssz_bytes: &[u8]) -> Option<T> {
    T::from_ssz_bytes(ssz_bytes).ok()
}
