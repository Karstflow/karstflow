/// Rent sysvar serialization wrapper.
///
/// Wraps the existing `Rent` type to provide account-level serialization.
/// Rent parameters control the minimum balance required for accounts
/// to remain alive on-chain.
use crate::Rent;

/// Serializable wrapper for the Rent sysvar.
///
/// Layout: lamports_per_byte_year(u64) + exemption_threshold(f64) + burn_percent(u8)
///         = 17 bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RentSysvar {
    pub rent: Rent,
}

impl RentSysvar {
    pub fn new(rent: Rent) -> Self {
        Self { rent }
    }

    /// Serialize to bytes for sysvar account data.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(17);
        buf.extend_from_slice(&self.rent.lamports_per_byte_year.to_le_bytes());
        buf.extend_from_slice(&self.rent.exemption_threshold.to_le_bytes());
        buf.push(self.rent.burn_percent);
        buf
    }

    /// Deserialize from sysvar account data bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 17 {
            return None;
        }
        let lamports_per_byte_year = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let exemption_threshold = f64::from_le_bytes(data[8..16].try_into().ok()?);
        let burn_percent = data[16];
        Some(Self {
            rent: Rent {
                lamports_per_byte_year,
                exemption_threshold,
                burn_percent,
            },
        })
    }
}

impl From<Rent> for RentSysvar {
    fn from(rent: Rent) -> Self {
        Self::new(rent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rent() -> Rent {
        Rent {
            lamports_per_byte_year: 3480,
            exemption_threshold: 2.0,
            burn_percent: 50,
        }
    }

    #[test]
    fn serialization_roundtrip() {
        let sysvar = RentSysvar::new(test_rent());
        let bytes = sysvar.to_bytes();
        assert_eq!(bytes.len(), 17);
        let restored = RentSysvar::from_bytes(&bytes).unwrap();
        assert_eq!(restored, sysvar);
    }

    #[test]
    fn from_bytes_rejects_too_short() {
        assert!(RentSysvar::from_bytes(&[0u8; 16]).is_none());
    }

    #[test]
    fn float_threshold_preserved() {
        let mut rent = test_rent();
        rent.exemption_threshold = 1.5;
        let sysvar = RentSysvar::new(rent);
        let restored = RentSysvar::from_bytes(&sysvar.to_bytes()).unwrap();
        assert!((restored.rent.exemption_threshold - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn from_rent_conversion() {
        let rent = test_rent();
        let sysvar: RentSysvar = rent.into();
        assert_eq!(sysvar.rent.burn_percent, 50);
    }

    #[test]
    fn burn_percent_byte() {
        let sysvar = RentSysvar::new(test_rent());
        let bytes = sysvar.to_bytes();
        assert_eq!(bytes[16], 50); // burn_percent is last byte
    }
}
