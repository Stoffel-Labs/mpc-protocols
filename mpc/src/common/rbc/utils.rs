use super::*;
use crate::common::rbc::ShardError;
use reed_solomon_erasure::galois_8::ReedSolomon;
use rs_merkle::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Encodes a given payload using Reed-Solomon erasure coding
pub fn encode_rs(
    payload: Vec<u8>,
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<Vec<u8>>, ShardError> {
    // Validate input parameters
    if data_shards == 0 || parity_shards == 0 {
        return Err(ShardError::Config("Shard counts must be > 0".to_string()));
    }

    // Make sure the payload is divisible across data shards
    let shard_size = (payload.len() + data_shards - 1) / data_shards;
    let mut shards = Vec::with_capacity(data_shards + parity_shards);

    // Fill data shards (pad last shard if needed)
    for i in 0..data_shards {
        let start = i * shard_size;

        let shard = if start < payload.len() {
            let end = usize::min(start + shard_size, payload.len());
            let mut s = payload[start..end].to_vec();
            s.resize(shard_size, 0); // pad if needed
            s
        } else {
            vec![0u8; shard_size] // completely padded shard
        };
        shards.push(shard);
    }

    // Add empty parity shards
    for _ in 0..parity_shards {
        shards.push(vec![0u8; shard_size]);
    }

    // Create Reed-Solomon instance
    let r = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| ShardError::Config(e.to_string()))?;

    // Encode to generate parity
    r.encode(&mut shards)
        .map_err(|e| ShardError::Failed(e.to_string()))?;

    Ok(shards)
}
/// Decodes and reconstructs original shards using Reed-Solomon
pub fn decode_rs(
    shards_map: HashMap<u32, Vec<u8>>,
    data_shards: usize,
    parity_shards: usize,
) -> Result<Vec<Vec<u8>>, ShardError> {
    let total_shards = data_shards + parity_shards;
    // Initialize the Reed-Solomon decoder
    let r = ReedSolomon::new(data_shards, parity_shards)
        .map_err(|e| ShardError::Config(e.to_string()))?;

    // Create a list of shard slots (None = missing)
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards];
    // Fill known shard positions
    for (&idx, shard) in &shards_map {
        if (idx as usize) < total_shards {
            shards[idx as usize] = Some(shard.clone());
        } else {
            return Err(ShardError::OutOfBounds(idx, total_shards - 1));
        }
    }
    // Attempt to reconstruct missing shards
    r.reconstruct(&mut shards)
        .map_err(|e| ShardError::Failed(e.to_string()))?;

    // Ensure all shards are present and unwrap them
    let result: Result<Vec<Vec<u8>>, _> = shards
        .into_iter()
        .map(|opt| opt.ok_or(ShardError::Incomplete))
        .collect();
    result
}
/// Reconstructs the original payload from decoded data shards
pub fn reconstruct_payload(
    decoded_shards: Vec<Vec<u8>>,
    original_len: usize,
    data_shards: usize,
) -> Result<Vec<u8>, ShardError> {
    if decoded_shards.len() < data_shards {
        return Err(ShardError::Incomplete);
    }
    // Concatenate only the data shards to form the original message
    let mut payload = decoded_shards
        .into_iter()
        .take(data_shards)
        .flatten()
        .collect::<Vec<u8>>();
    // Validate and truncate to the original message length
    if original_len > payload.len() {
        return Err(ShardError::Config(
            "Original length exceeds payload".to_string(),
        ));
    }
    // Truncate to original message length
    payload.truncate(original_len);

    Ok(payload)
}

#[derive(Clone)]
pub struct Sha256Algorithm {}

impl Hasher for Sha256Algorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// Hash a single shard using SHA-256.
pub fn hash(shard: Vec<u8>) -> [u8; 32] {
    Sha256Algorithm::hash(&shard)
}
/// Generate a Merkle tree from a list of shards.
pub fn gen_merkletree(shards: Vec<Vec<u8>>) -> MerkleTree<Sha256Algorithm> {
    let leaves: Vec<[u8; 32]> = shards.iter().map(|x| hash(x.clone())).collect();
    MerkleTree::<Sha256Algorithm>::from_leaves(&leaves)
}
/// Deserialize a Merkle proof from raw bytes (excluding the root).
pub fn get_merkle_proof(proof: Vec<u8>) -> Result<MerkleProof<Sha256Algorithm>, ShardError> {
    if proof.len() <= 32 {
        return Err(ShardError::Merkle("Invalid fingerprint length".to_string()));
    }

    MerkleProof::<Sha256Algorithm>::try_from(&proof[32..])
        .map_err(|e| ShardError::Merkle(e.to_string()))
}
/// Verify a Merkle proof for a given shard and index.
pub fn verify_merkle(id: u32, n: u32, proof: Vec<u8>, shard: Vec<u8>) -> Result<bool, ShardError> {
    if proof.len() < 32 {
        return Err(ShardError::Merkle("Invalid fingerprint length".to_string()));
    }
    let root: [u8; 32] = proof[0..32]
        .try_into()
        .map_err(|_| ShardError::Merkle("Failed to extract Merkle root".to_string()))?;
    let proof = get_merkle_proof(proof)?;
    let leaf_hash = hash(shard.clone());

    Ok(proof.verify(root, &vec![id as usize], &[leaf_hash], n as usize))
}

/// Generate Merkle proofs for all leaves and return them as a map.
pub fn generate_merkle_proofs_map(
    shards: Vec<Vec<u8>>,
    n: usize,
) -> Result<HashMap<usize, Vec<u8>>, ShardError> {
    let tree = gen_merkletree(shards);

    // ensure tree is valid
    if tree.root().is_none() {
        return Err(ShardError::Merkle(
            "Failed to extract Merkle root".to_string(),
        ));
    }

    let mut proofs_map = HashMap::with_capacity(n);
    for i in 0..n {
        let proof_bytes = tree.proof(&[i]).to_bytes();
        proofs_map.insert(i, proof_bytes);
    }

    Ok(proofs_map)
}

//Set value||roundid
pub fn set_value_round(bit: bool, number: u32) -> Vec<u8> {
    let mut vec = Vec::with_capacity(5);

    // Store the bit in the least significant bit of the first byte
    let first_byte = if bit { 1u8 } else { 0u8 };
    vec.push(first_byte);

    // Store the u32 number in little-endian order
    vec.extend_from_slice(&number.to_le_bytes());

    vec
}
//Get round id and value
pub fn get_value_round(data: &[u8]) -> Option<(bool, u32)> {
    if data.len() < 5 {
        return None;
    }

    let bit = data[0] & 1 != 0;

    let number_bytes = &data[1..5];
    let number = u32::from_le_bytes(number_bytes.try_into().ok()?);

    Some((bit, number))
}
/// Extracts the least significant bit from the first byte as a boolean.
pub fn get_value(data: &[u8]) -> Option<bool> {
    data.get(0).map(|byte| byte & 1 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_reed_solomon_encode_decode_roundtrip() {
        let payload = b"Hello, world!".to_vec();
        let data_shards = 4;
        let parity_shards = 2;

        // Encode
        let shards = encode_rs(payload.clone(), data_shards, parity_shards)
            .expect("Encoding should succeed");

        // Drop one shard to simulate data loss
        let mut shards_map = HashMap::new();
        for (i, shard) in shards.iter().enumerate() {
            if i != 1 {
                // Drop shard 1
                shards_map.insert(i as u32, shard.clone());
            }
        }

        // Decode
        let decoded_shards =
            decode_rs(shards_map, data_shards, parity_shards).expect("Decoding should succeed");

        // Reconstruct payload
        let reconstructed = reconstruct_payload(decoded_shards, payload.len(), data_shards)
            .expect("Reconstruction should succeed");

        assert_eq!(payload, reconstructed);
    }

    #[test]
    fn test_merkle_tree_and_proof_verification() {
        let payload = b"Merkle tree test!".to_vec();
        let data_shards = 4;
        let parity_shards = 2;

        // Encode and generate Merkle tree
        let shards = encode_rs(payload.clone(), data_shards, parity_shards)
            .expect("Encoding should succeed");
        let tree = gen_merkletree(shards.clone());

        // Generate proofs
        let proofs_map = generate_merkle_proofs_map(shards.clone(), shards.len())
            .expect("Proof generation should succeed");

        for (i, shard) in shards.iter().enumerate() {
            let mut proof_with_root = vec![];
            proof_with_root.extend_from_slice(&tree.root().unwrap()); // prepend root
            proof_with_root.extend_from_slice(&proofs_map[&i]);

            let verified = verify_merkle(
                i as u32,
                shards.len() as u32,
                proof_with_root,
                shard.clone(),
            )
            .expect("Verification should succeed");

            assert!(verified, "Merkle proof for shard {} failed", i);
        }
    }

    #[test]
    fn test_decode_failure_with_insufficient_data() {
        let payload = b"Test failure!".to_vec();
        let data_shards = 3;
        let parity_shards = 2;

        let shards = encode_rs(payload.clone(), data_shards, parity_shards)
            .expect("Encoding should succeed");

        // Only provide 2 shards (less than data_shards)
        let mut shards_map = HashMap::new();
        shards_map.insert(0, shards[0].clone());
        shards_map.insert(1, shards[1].clone());

        let result = decode_rs(shards_map, data_shards, parity_shards);
        assert!(
            result.is_err(),
            "Decoding should fail due to insufficient data shards"
        );
    }
}
