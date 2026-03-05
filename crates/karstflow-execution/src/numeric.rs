pub(crate) fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub(crate) fn usize_to_u128_saturating(value: usize) -> u128 {
    u128::try_from(value).unwrap_or(u128::MAX)
}

pub(crate) fn u128_to_u64_saturating(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub(crate) fn u128_to_usize_saturating(value: u128) -> usize {
    if value > usize_to_u128_saturating(usize::MAX) {
        usize::MAX
    } else {
        value as usize
    }
}

#[cfg(test)]
mod tests {
    use super::{
        u128_to_u64_saturating, u128_to_usize_saturating, usize_to_u128_saturating,
        usize_to_u64_saturating,
    };

    #[test]
    fn usize_to_u64_saturates_at_max() {
        assert_eq!(usize_to_u64_saturating(usize::MAX), u64::MAX);
    }

    #[test]
    fn usize_to_u128_is_exact_for_usize_max() {
        assert_eq!(usize_to_u128_saturating(usize::MAX), usize::MAX as u128);
    }

    #[test]
    fn u128_to_u64_saturates_above_range() {
        assert_eq!(u128_to_u64_saturating(u128::MAX), u64::MAX);
    }

    #[test]
    fn u128_to_usize_saturates_above_range() {
        assert_eq!(u128_to_usize_saturating(u128::MAX), usize::MAX);
    }
}
