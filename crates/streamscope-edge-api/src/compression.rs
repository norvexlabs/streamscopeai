//! Gzip on the sync answer. A tenant body repeats the same seeded rule and
//! profile text, so a cold edge's answers compress several-fold. The edge asks
//! with `Accept-Encoding: gzip`; admin-api's compression layer on the sync
//! route answers gzip for a large answer and plain for a small one.

use std::io::Read;

pub const GZIP: &str = "gzip";

/// Decompress, refusing an output larger than `cap`: the decoded size, not the
/// transferred one, is what a hostile or broken answer could inflate.
pub fn gunzip_capped(bytes: &[u8], cap: usize) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes).take(cap as u64 + 1).read_to_end(&mut out)?;
    if out.len() > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("decoded answer exceeds {cap} bytes"),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn a_round_trip_returns_the_bytes() {
        let body = br#"{"resources":[{"x":"same text same text same text"}]}"#.repeat(100);
        assert_eq!(gunzip_capped(&gzip(&body), body.len()).unwrap(), body);
    }

    #[test]
    fn a_decoded_answer_past_the_cap_is_refused_and_one_at_it_is_not() {
        let packed = gzip(&[b'a'; 10_000]);
        assert!(gunzip_capped(&packed, 9_999).is_err());
        assert_eq!(gunzip_capped(&packed, 10_000).unwrap().len(), 10_000);
    }

    #[test]
    fn bytes_that_are_not_gzip_are_refused() {
        assert!(gunzip_capped(b"{\"plain\": true}", 1_000).is_err());
    }
}
