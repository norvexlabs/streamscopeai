//! Canonical bytes and content digests for config resources.
//!
//! A resource's digest is `sha256` over its canonical bytes:
//! `serde_json::to_vec(&serde_json::to_value(body))`. serde_json is built
//! without `preserve_order`, so a `Value` object is a `BTreeMap` and every key
//! comes out sorted at every depth — a `HashMap` field included. An array keeps
//! the order it was given in: a set on the wire must be a `BTreeSet`, and a
//! `Vec` must be collected in a total order. Two replicas building the same
//! rows must produce the same bytes, or an edge is pushed the same resource
//! forever.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

/// A sha256 content digest, carried as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.to_hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Digest {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|e| format!("invalid digest: {e}"))?;
        Ok(Self(out))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl utoipa::PartialSchema for Digest {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::SchemaType::new(utoipa::openapi::schema::Type::String))
            .description(Some("sha256, lowercase hex"))
            .into()
    }
}

impl utoipa::ToSchema for Digest {}

/// The canonical value of `body`: what is digested and what is sent.
pub fn canonical_value<T: Serialize>(body: &T) -> Result<serde_json::Value, serde_json::Error> {
    serde_json::to_value(body)
}

/// The digest of a canonical value.
pub fn digest_of(value: &serde_json::Value) -> Result<Digest, serde_json::Error> {
    Ok(Digest::of(&serde_json::to_vec(value)?))
}

/// The digest of a held set: sha256 over one `"<resource>\t<digest hex>\n"`
/// line per entry, in bytewise order of the resource name. Both ends compute
/// it with this function, so the encoding cannot drift between them.
pub fn held_digest<'a, I>(held: I) -> Digest
where
    I: IntoIterator<Item = (&'a str, &'a Digest)>,
{
    let sorted: BTreeMap<&str, &Digest> = held.into_iter().collect();
    let mut h = Sha256::new();
    for (resource, digest) in sorted {
        h.update(resource.as_bytes());
        h.update(b"\t");
        h.update(digest.to_hex().as_bytes());
        h.update(b"\n");
    }
    Digest(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn a_map_inserted_out_of_order_encodes_sorted() {
        // Fails if serde_json's `preserve_order` is ever unified into the
        // build: object keys would then follow insertion (or hash) order.
        let mut m = HashMap::new();
        for k in ["zeta", "alpha", "mu", "beta", "omega", "kappa"] {
            m.insert(k.to_string(), serde_json::json!({ "y": 1, "b": 2 }));
        }
        let bytes = serde_json::to_vec(&canonical_value(&m).unwrap()).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"alpha":{"b":2,"y":1},"beta":{"b":2,"y":1},"kappa":{"b":2,"y":1},"mu":{"b":2,"y":1},"omega":{"b":2,"y":1},"zeta":{"b":2,"y":1}}"#
        );
    }

    #[test]
    fn equal_content_has_one_digest_and_different_content_another() {
        let a = canonical_value(&serde_json::json!({ "a": [1, 2], "b": "x" })).unwrap();
        let b = canonical_value(&serde_json::json!({ "b": "x", "a": [1, 2] })).unwrap();
        let c = canonical_value(&serde_json::json!({ "b": "x", "a": [2, 1] })).unwrap();
        assert_eq!(digest_of(&a).unwrap(), digest_of(&b).unwrap());
        assert_ne!(digest_of(&a).unwrap(), digest_of(&c).unwrap());
    }

    #[test]
    fn held_digest_is_the_documented_encoding_in_any_input_order() {
        let g = Digest::of(b"g");
        let t = Digest::of(b"t");
        let expected = Digest::of(format!("global\t{g}\ntenant:1\t{t}\n").as_bytes());
        assert_eq!(held_digest([("tenant:1", &t), ("global", &g)]), expected);
        assert_eq!(held_digest([("global", &g), ("tenant:1", &t)]), expected);
        assert_ne!(held_digest([("global", &g)]), expected);
    }

    #[test]
    fn digest_round_trips_as_hex_and_refuses_anything_else() {
        let d = Digest::of(b"x");
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), d);
        assert!(serde_json::from_str::<Digest>("\"abc\"").is_err());
        assert!(serde_json::from_str::<Digest>(&format!("\"{}\"", "z".repeat(64))).is_err());
    }
}
