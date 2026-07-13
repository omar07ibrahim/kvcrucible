//! Internal semantic fingerprints for normalized envelope mutations.

use std::io::{self, Write};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ir::EventEnvelope;

/// Opaque digest that cannot be serialized into or deserialized from the IR.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct SemanticFingerprint([u8; 32]);

/// Fingerprint plus the canonical work charged to its trace budget.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Computed {
    pub(crate) fingerprint: SemanticFingerprint,
    pub(crate) canonical_bytes: usize,
}

/// Redacted failures from bounded canonical hashing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    /// The canonical serializer rejected a typed value.
    Canonicalization,
    /// Canonical mutation bytes exceeded their inclusive ceiling.
    ResourceLimit {
        /// Configured inclusive maximum.
        maximum: usize,
        /// First byte count known to exceed the maximum.
        observed: usize,
    },
    /// Canonical-byte accounting overflowed `usize`.
    CounterOverflow,
}

/// Hash only the complete normalized `mutations` array of one valid envelope.
///
/// The caller must first validate the envelope under the active structural
/// limits. RFC 8785 object sorting can buffer one already-bounded object, while
/// this writer prevents the complete canonical array from growing unbounded.
pub(crate) fn envelope(envelope: &EventEnvelope, maximum: usize) -> Result<Computed, Error> {
    value(&envelope.mutations, maximum)
}

fn value<T: Serialize>(value: &T, maximum: usize) -> Result<Computed, Error> {
    let mut writer = HashWriter::new(maximum);
    let serialization = serde_json_canonicalizer::to_writer(value, &mut writer);
    if let Some(failure) = writer.failure {
        return Err(failure);
    }
    serialization.map_err(|_| Error::Canonicalization)?;
    Ok(writer.finish())
}

struct HashWriter {
    hasher: Sha256,
    maximum: usize,
    written: usize,
    failure: Option<Error>,
}

impl HashWriter {
    fn new(maximum: usize) -> Self {
        Self {
            hasher: Sha256::new(),
            maximum,
            written: 0,
            failure: None,
        }
    }

    fn finish(self) -> Computed {
        Computed {
            fingerprint: SemanticFingerprint(self.hasher.finalize().into()),
            canonical_bytes: self.written,
        }
    }

    fn fail(&mut self, error: Error) -> io::Error {
        self.failure = Some(error);
        io::Error::other("semantic fingerprint writer rejected output")
    }
}

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(observed) = self.written.checked_add(bytes.len()) else {
            return Err(self.fail(Error::CounterOverflow));
        };
        if observed > self.maximum {
            return Err(self.fail(Error::ResourceLimit {
                maximum: self.maximum,
                observed,
            }));
        }
        self.hasher.update(bytes);
        self.written = observed;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde::{Serialize, Serializer, ser::Error as _};
    use sha2::{Digest, Sha256};

    use super::{Error, envelope as fingerprint, value};
    use crate::ir::{
        CacheGroup, DecimalU64, EventEnvelope, IrValue, Mutation, OpaqueHash, Origin, StorageMedium,
    };

    fn clear(metadata: BTreeMap<String, IrValue>) -> Mutation {
        Mutation::Clear { metadata }
    }

    fn envelope_with(mutations: Vec<Mutation>) -> EventEnvelope {
        EventEnvelope {
            envelope_id: "envelope-a".to_owned(),
            stream_id: "stream-a".to_owned(),
            cursor: DecimalU64::new(7),
            origin: Origin::Live,
            mutations,
            extensions: BTreeMap::new(),
        }
    }

    fn hex(bytes: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    #[test]
    fn unicode_vector_pins_the_jcs_preimage_and_sha256_digest() {
        let metadata = BTreeMap::from([
            ("\r".to_owned(), IrValue::String("cr".to_owned())),
            ("1".to_owned(), IrValue::String("one".to_owned())),
            ("\u{80}".to_owned(), IrValue::String("ctl".to_owned())),
            ("ö".to_owned(), IrValue::String("latin".to_owned())),
            ("€".to_owned(), IrValue::String("euro".to_owned())),
            ("😀".to_owned(), IrValue::String("emoji".to_owned())),
            ("\u{fb33}".to_owned(), IrValue::String("hebrew".to_owned())),
        ]);
        let envelope = envelope_with(vec![clear(metadata)]);
        let canonical = serde_json_canonicalizer::to_vec(&envelope.mutations).unwrap();
        let expected = concat!(
            r#"[{"metadata":{"\r":"cr","1":"one","":"ctl","ö":"latin","€":"euro","#,
            r#""😀":"emoji",""#,
            "\u{fb33}",
            r#"":"hebrew"},"op":"clear"}]"#,
        );

        assert_eq!(canonical, expected.as_bytes());
        let fingerprint = fingerprint(&envelope, canonical.len()).unwrap();
        assert_eq!(
            hex(&fingerprint.fingerprint.0),
            "655bdc2876b74e51d342a86279be68efedac864a2438244ed7bdbc3b7b9a76a7"
        );
        assert_eq!(fingerprint.canonical_bytes, canonical.len());
    }

    #[test]
    fn empty_mutations_have_a_known_digest_and_exclude_jsonl_framing() {
        let envelope = envelope_with(Vec::new());
        let fingerprint = fingerprint(&envelope, 2).unwrap();
        assert_eq!(
            hex(&fingerprint.fingerprint.0),
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );

        let framed = Sha256::digest(b"[]\n");
        assert_ne!(fingerprint.fingerprint.0.as_slice(), framed.as_slice());
    }

    #[test]
    fn transport_fields_do_not_change_the_semantic_fingerprint() {
        let mutation = clear(BTreeMap::from([(
            "key".to_owned(),
            IrValue::String("value".to_owned()),
        )]));
        let first = envelope_with(vec![mutation.clone()]);
        let mut second = envelope_with(vec![mutation]);
        second.envelope_id = "different-envelope".to_owned();
        second.stream_id = "different-stream".to_owned();
        second.cursor = DecimalU64::new(u64::MAX);
        second.origin = Origin::Replay;
        second
            .extensions
            .insert("ignored".to_owned(), IrValue::Bool(true));

        assert!(
            fingerprint(&first, 1024).unwrap().fingerprint
                == fingerprint(&second, 1024).unwrap().fingerprint
        );
    }

    #[test]
    fn mutation_content_order_and_hash_order_are_significant() {
        let left = clear(BTreeMap::from([(
            "side".to_owned(),
            IrValue::String("left".to_owned()),
        )]));
        let right = clear(BTreeMap::from([(
            "side".to_owned(),
            IrValue::String("right".to_owned()),
        )]));
        let left_only = envelope_with(vec![left.clone()]);
        let right_only = envelope_with(vec![right.clone()]);
        let ordered = envelope_with(vec![left.clone(), right.clone()]);
        let reversed = envelope_with(vec![right, left]);

        assert!(
            fingerprint(&left_only, 4096).unwrap().fingerprint
                != fingerprint(&right_only, 4096).unwrap().fingerprint
        );
        assert!(
            fingerprint(&ordered, 4096).unwrap().fingerprint
                != fingerprint(&reversed, 4096).unwrap().fingerprint
        );

        let store = |values: [u64; 2]| Mutation::StoreRun {
            hashes: values
                .into_iter()
                .map(|value| OpaqueHash::U64 {
                    value: DecimalU64::new(value),
                })
                .collect(),
            lineage: None,
            token_count: None,
            token_evidence: None,
            block_size: None,
            group: CacheGroup::Unspecified,
            medium: StorageMedium::Unspecified,
            block_metadata: None,
            metadata: BTreeMap::new(),
        };
        let hashes_12 = envelope_with(vec![store([1, 2])]);
        let hashes_21 = envelope_with(vec![store([2, 1])]);
        assert!(
            fingerprint(&hashes_12, 4096).unwrap().fingerprint
                != fingerprint(&hashes_21, 4096).unwrap().fingerprint
        );
    }

    #[test]
    fn canonical_byte_ceiling_is_inclusive_and_fails_before_hashing_excess() {
        let envelope = envelope_with(vec![clear(BTreeMap::new())]);
        let canonical = serde_json_canonicalizer::to_vec(&envelope.mutations).unwrap();

        assert!(fingerprint(&envelope, canonical.len()).is_ok());
        assert!(matches!(
            fingerprint(&envelope, canonical.len() - 1),
            Err(Error::ResourceLimit {
                maximum,
                observed,
            }) if maximum == canonical.len() - 1 && observed > maximum
        ));
    }

    #[test]
    fn canonicalization_errors_discard_serializer_messages() {
        const SECRET: &str = "ZXQ_SERIALIZER_SECRET_27";

        struct Failing;

        impl Serialize for Failing {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                Err(S::Error::custom(SECRET))
            }
        }

        let error = value(&Failing, usize::MAX).err().unwrap();
        assert_eq!(error, Error::Canonicalization);
        assert!(!format!("{error:?}").contains(SECRET));
    }
}
