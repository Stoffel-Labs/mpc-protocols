//! Shared bincode configuration for all MPC wire messages.
//!
//! Varint-encodes length prefixes and enum discriminants: most values here (small vecs, small
//! enum tags) fit in one byte, whereas bincode's fixint default always spends 4 (enum tag) or 8
//! (length prefix) bytes regardless of the actual value. Payload bytes (field elements, curve
//! points, signatures) are unaffected either way. Every serializer/deserializer pair on the wire
//! must go through this module so both sides agree on the encoding.

use bincode::Options;
use serde::{Deserialize, Serialize};

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .allow_trailing_bytes()
}

/// Serializes `value` using the crate's wire-format configuration.
pub fn serialize<T>(value: &T) -> Result<Vec<u8>, Box<bincode::ErrorKind>>
where
    T: ?Sized + Serialize,
{
    options().serialize(value)
}

/// Deserializes `bytes` using the crate's wire-format configuration.
pub fn deserialize<'a, T>(bytes: &'a [u8]) -> Result<T, Box<bincode::ErrorKind>>
where
    T: Deserialize<'a>,
{
    options().deserialize(bytes)
}

/// Deserializes `bytes` using the crate's wire-format configuration, rejecting input whose
/// encoded size exceeds `limit`.
pub fn deserialize_limited<'a, T>(bytes: &'a [u8], limit: u64) -> Result<T, Box<bincode::ErrorKind>>
where
    T: Deserialize<'a>,
{
    options().with_limit(limit).deserialize(bytes)
}
