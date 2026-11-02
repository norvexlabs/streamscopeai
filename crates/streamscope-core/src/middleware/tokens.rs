//! Central token estimation module.
//!
//! All `bytes / 4` and `chars / 4` estimation goes through here.
//! The `_body` parameter is reserved for future smarter estimation
//! (parse content, per-model ratios).

const CHARS_PER_TOKEN: usize = 4;

/// Estimate input tokens from raw body byte count.
pub fn estimate_input_tokens_from_bytes(byte_count: usize, _body: Option<&[u8]>) -> u32 {
    (byte_count / CHARS_PER_TOKEN).max(1) as u32
}

/// Estimate tokens from a character count (for pre-parsed content).
pub fn estimate_tokens_from_chars(char_count: usize) -> u32 {
    (char_count / CHARS_PER_TOKEN).max(1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_from_bytes_basic() {
        assert_eq!(estimate_input_tokens_from_bytes(400, None), 100);
    }

    #[test]
    fn estimate_from_bytes_minimum() {
        assert_eq!(estimate_input_tokens_from_bytes(0, None), 1);
    }

    #[test]
    fn estimate_from_chars() {
        assert_eq!(estimate_tokens_from_chars(1000), 250);
    }

    #[test]
    fn estimate_from_chars_minimum() {
        assert_eq!(estimate_tokens_from_chars(0), 1);
    }
}
