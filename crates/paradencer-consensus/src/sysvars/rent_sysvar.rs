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
