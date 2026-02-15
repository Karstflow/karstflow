//! Utility functions for cryptographic operations

use crate::{CryptoError, CryptoResult};

/// Constant-time equality comparison for slices
///
/// This prevents timing attacks when comparing sensitive data.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Secure zero memory
///
/// Ensures that sensitive data is properly cleared from memory.
pub fn secure_zero(data: &mut [u8]) {
    // Use volatile write to prevent compiler optimization
    for byte in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

/// Convert bytes to hex string
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert hex string to bytes
pub fn from_hex(hex: &str) -> CryptoResult<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(CryptoError::InternalError("Odd hex length".to_string()));
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| CryptoError::InternalError(format!("Invalid hex: {}", e)))
        })
        .collect()
}

/// XOR two byte slices
///
/// Panics if slices have different lengths.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(
        a.len(),
        b.len(),
        "XOR requires equal-length byte slices"
    );

    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Generate a random 32-byte key (for testing)
#[cfg(test)]
pub fn random_key() -> [u8; 32] {
    use rand::Rng;
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    key
}

/// Generate random bytes (for testing)
#[cfg(test)]
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand::Rng;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        let d = [1u8, 2, 3];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }

    #[test]
    fn test_secure_zero() {
        let mut data = [0xFFu8; 32];
        secure_zero(&mut data);
        assert_eq!(data, [0u8; 32]);
    }

    #[test]
    fn test_to_hex() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(to_hex(&bytes), "deadbeef");

        let empty: [u8; 0] = [];
        assert_eq!(to_hex(&empty), "");
    }

    #[test]
    fn test_from_hex() {
        let hex = "deadbeef";
        let bytes = from_hex(hex).unwrap();
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let empty = "";
        assert_eq!(from_hex(empty).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_from_hex_invalid() {
        assert!(from_hex("xyz").is_err());
        assert!(from_hex("abc").is_err()); // Odd length
    }

    #[test]
    fn test_xor_bytes() {
        let a = [0xAA, 0xBB, 0xCC];
        let b = [0xFF, 0x00, 0xFF];
        let result = xor_bytes(&a, &b);
        assert_eq!(result, vec![0x55, 0xBB, 0x33]);
    }

    #[test]
    #[should_panic]
    fn test_xor_bytes_different_lengths() {
        let a = [1, 2, 3];
        let b = [1, 2];
        xor_bytes(&a, &b);
    }

    #[test]
    fn test_random_key() {
        let key1 = random_key();
        let key2 = random_key();

        // Keys should be different
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(100);
        let bytes2 = random_bytes(100);

        assert_eq!(bytes1.len(), 100);
        assert_eq!(bytes2.len(), 100);

        // Should be different
        assert_ne!(bytes1, bytes2);
    }
}
