//! Independent conformance helpers for the Phase 25 ledger serialization.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Serializes a `serde_json::Value` with the deterministic map ordering used by
/// the Phase 25 producer and appends the contractual newline.
///
/// # Errors
///
/// Returns the underlying JSON serialization error.
pub fn canonical_value(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Returns a lowercase SHA-256 digest.
#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{canonical_value, sha256};
    use serde_json::Value;

    const OBSERVATION: &[u8] = include_bytes!("../reproducer/fixtures/observation.json");
    const PROJECTION: &[u8] = include_bytes!("../reproducer/fixtures/ledger-projection.json");

    #[test]
    fn observation_payload_is_hashed_as_exact_bytes() {
        assert_eq!(
            sha256(OBSERVATION),
            "2afcec764895fa2ad4f1d6cad0d6a2ce4cc9f68515611eb488195a0d580ee286"
        );
    }

    #[test]
    fn value_projection_has_deterministic_key_order_and_newline()
    -> Result<(), Box<dyn std::error::Error>> {
        let parsed: Value = serde_json::from_slice(PROJECTION)?;
        let serialized = canonical_value(&parsed)?;
        assert_eq!(serialized, PROJECTION);
        Ok(())
    }
}
