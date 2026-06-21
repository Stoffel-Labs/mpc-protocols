use ark_serialize::{CanonicalDeserialize, SerializationError};

pub fn deser_bounded_vec<T: CanonicalDeserialize>(
    r: &mut &[u8],
    max: usize,
) -> Result<Vec<T>, SerializationError> {
    if r.len() < 8 {
        return Err(SerializationError::InvalidData);
    }
    let (head, tail) = r.split_at(8);
    let len = u64::from_le_bytes(head.try_into().unwrap()) as usize;
    if len > max {
        return Err(SerializationError::InvalidData);
    }
    *r = tail;
    let mut values = Vec::new();
    for _ in 0..len {
        values.push(T::deserialize_compressed(&mut *r)?);
    }
    Ok(values)
}
