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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_nonzero_u64_rejects_zero() {
        assert!(ensure_nonzero_u64("field", 0).is_err());
    }

    #[test]
    fn ensure_nonzero_u64_accepts_positive() {
        assert!(ensure_nonzero_u64("field", 1).is_ok());
        assert!(ensure_nonzero_u64("field", u64::MAX).is_ok());
    }

    #[test]
    fn ensure_nonzero_u32_rejects_zero() {
        assert!(ensure_nonzero_u32("field", 0).is_err());
    }

    #[test]
    fn ensure_nonzero_u32_accepts_positive() {
        assert!(ensure_nonzero_u32("field", 1).is_ok());
    }

    #[test]
    fn ensure_nonzero_u8_rejects_zero() {
        assert!(ensure_nonzero_u8("field", 0).is_err());
    }

    #[test]
    fn ensure_nonzero_u8_accepts_positive() {
        assert!(ensure_nonzero_u8("field", 255).is_ok());
    }

    #[test]
    fn ensure_nonzero_usize_rejects_zero() {
        assert!(ensure_nonzero_usize("field", 0).is_err());
    }

    #[test]
    fn ensure_nonzero_usize_accepts_positive() {
        assert!(ensure_nonzero_usize("field", 42).is_ok());
    }
}
