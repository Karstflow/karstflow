use crate::{ConfigError, Result};

pub(super) fn ensure_nonzero_u64(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        return Err(ConfigError::NonPositiveValue {
            name: name.to_string(),
        });
    }
    Ok(())
}

pub(super) fn ensure_nonzero_u32(name: &str, value: u32) -> Result<()> {
    if value == 0 {
        return Err(ConfigError::NonPositiveValue {
            name: name.to_string(),
        });
    }
    Ok(())
}

pub(super) fn ensure_nonzero_u8(name: &str, value: u8) -> Result<()> {
    if value == 0 {
        return Err(ConfigError::NonPositiveValue {
            name: name.to_string(),
        });
    }
    Ok(())
}

pub(super) fn ensure_nonzero_usize(name: &str, value: usize) -> Result<()> {
    if value == 0 {
        return Err(ConfigError::NonPositiveValue {
            name: name.to_string(),
        });
    }
    Ok(())
}
