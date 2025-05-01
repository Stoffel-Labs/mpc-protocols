use reed_solomon_erasure::galois_8::ReedSolomon;
use rs_merkle::*;
use sha2::{digest::FixedOutput, Digest, Sha256};
use std::collections::HashMap;

pub fn encode_rs(payload: Vec<u8>, data_shards: usize, parity_shards: usize) -> Vec<Vec<u8>> {
    assert!(data_shards > 0 && parity_shards > 0);

    // Make sure the payload is divisible across data shards
    let shard_size = (payload.len() + data_shards - 1) / data_shards;
    let mut shards: Vec<Vec<u8>> = vec![];

    // Fill data shards (pad last shard if needed)
    for i in 0..data_shards {
        let start = i * shard_size;
        let end = usize::min(start + shard_size, payload.len());
        let mut shard = payload[start..end].to_vec();
        shard.resize(shard_size, 0); // pad with zeros
        shards.push(shard);
    }

    // Add empty parity shards
    for _ in 0..parity_shards {
        shards.push(vec![0u8; shard_size]);
    }

    // Create Reed-Solomon instance
    let r = ReedSolomon::new(data_shards, parity_shards).expect("Invalid shard configuration");

    // Encode to generate parity
    r.encode(&mut shards).expect("Encoding failed");

    shards
}
pub fn decode_rs(
    shards_map: HashMap<u32, Vec<u8>>,
    data_shards: usize,
    parity_shards: usize,
) -> Vec<Vec<u8>> {
    let total_shards = data_shards + parity_shards;
    let r = ReedSolomon::new(data_shards, parity_shards).expect("Invalid shard configuration");

    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
    for (&idx, shard) in &shards_map {
        if (idx as usize) < total_shards {
            shards[idx as usize] = Some(shard.clone());
        }
    }

    r.reconstruct(&mut shards).expect("Reconstruction failed");

    // Convert all Option<Vec<u8>> to Vec<u8>
    shards
        .into_iter()
        .map(|opt| opt.expect("Missing shard after reconstruction"))
        .collect()
}
pub fn reconstruct_payload(
    decoded_shards: Vec<Vec<u8>>,
    original_len: usize,
    data_shards: usize,
) -> Vec<u8> {
    // Take only the data shards (original data before parity was added)
    let mut payload = decoded_shards
        .into_iter()
        .take(data_shards)
        .flatten()
        .collect::<Vec<u8>>();

    // Truncate to original message length
    payload.truncate(original_len);

    payload
}

#[derive(Clone)]
pub struct Sha256Algorithm {}

impl Hasher for Sha256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(data);
        <[u8; 32]>::from(hasher.finalize_fixed())
    }
}

pub fn hash(shard: Vec<u8>) -> [u8; 32] {
    Sha256Algorithm::hash(&shard)
}
pub fn gen_merkletree(shards: Vec<Vec<u8>>) -> MerkleTree<Sha256Algorithm> {
    let leaves: Vec<[u8; 32]> = shards.iter().map(|x| Sha256Algorithm::hash(x)).collect();
    MerkleTree::<Sha256Algorithm>::from_leaves(&leaves)
}
pub fn get_merkle_proof(proof: Vec<u8>) -> Result<MerkleProof<Sha256Algorithm>, Error> {
    let proof = MerkleProof::<Sha256Algorithm>::try_from(&proof[32..]);
    proof
}
pub fn verify_merkle(
    id: u32,
    n: u32,
    fingerprint: Vec<u8>,
    shard: Vec<u8>,
) -> Result<bool, String> {
    let root: [u8; 32] = fingerprint[0..32]
        .try_into()
        .expect("slice with incorrect length");
    let proof = get_merkle_proof(fingerprint).map_err(|e| e.to_string())?;
    let leaf_hash = hash(shard.clone());

    Ok(proof.verify(root, &vec![id as usize], &[leaf_hash], n as usize))
}

pub fn generate_merkle_proofs_map(
    shards: Vec<Vec<u8>>,
    n: usize,
) -> Result<HashMap<usize, Vec<u8>>, String> {
    let tree = gen_merkletree(shards);

    tree.root().ok_or("Failed to get Merkle root")?; // ensure tree is valid

    let mut proofs_map = HashMap::with_capacity(n);
    for i in 0..n {
        let proof_bytes = tree.proof(&[i]).to_bytes();
        proofs_map.insert(i, proof_bytes);
    }

    Ok(proofs_map)
}
