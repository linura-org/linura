use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicU8, Ordering};

use linura_transaction::{ContentDigest, TransactionStoreError, digest_bytes};
use sha2::{Digest, Sha256};

#[cfg(not(target_has_atomic = "8"))]
compile_error!("linura-persistence-sqlite requires atomic 8-bit stores for non-elidable secret scrubbing");

pub(crate) const INTEGRITY_KEY_BYTES: usize = 32;
pub(crate) const INTEGRITY_TAG_BYTES: usize = 32;
const SHA256_BLOCK_BYTES: usize = 64;

/// Independent secret used only to authenticate SQLite records.
///
/// Production composition roots must provision the same protected 256-bit
/// value on restart. SQLite stores only a domain-separated fingerprint and
/// per-record HMACs; neither reveals this key.
pub struct SqliteIntegrityKey {
    bytes: Vec<u8>,
    // Fixed-key HMAC pads have exactly the key's protected lifetime. Keeping
    // them here avoids making and scrubbing fresh key copies for every row.
    pads: Box<[[u8; SHA256_BLOCK_BYTES]; 2]>,
}

impl Debug for SqliteIntegrityKey {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteIntegrityKey")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Drop for SqliteIntegrityKey {
    fn drop(&mut self) {
        self.scrub();
    }
}

impl SqliteIntegrityKey {
    fn scrub(&mut self) {
        scrub_secret(&mut self.bytes);
        scrub_secret(&mut self.pads[0]);
        scrub_secret(&mut self.pads[1]);
    }

    pub fn new(mut bytes: Vec<u8>) -> Result<Self, TransactionStoreError> {
        validate_integrity_key_bytes(&mut bytes)?;
        let mut pads = Box::new([[0x36; SHA256_BLOCK_BYTES], [0x5c; SHA256_BLOCK_BYTES]]);
        for (index, byte) in bytes.iter().enumerate() {
            pads[0][index] ^= byte;
            pads[1][index] ^= byte;
        }
        Ok(Self { bytes, pads })
    }

    #[must_use]
    pub fn fingerprint(&self) -> ContentDigest {
        digest_bytes(
            "linura.sqlite.record-integrity-key-fingerprint.v1",
            &self.bytes,
        )
    }

    pub(crate) fn tag(
        &self,
        record_domain: &str,
        canonical: &[u8],
    ) -> Result<[u8; INTEGRITY_TAG_BYTES], TransactionStoreError> {
        Ok(hmac_sha256(
            &self.pads[0],
            &self.pads[1],
            [
                b"linura.sqlite.record-integrity.v1".as_slice(),
                record_domain.as_bytes(),
                canonical,
            ],
        ))
    }

    #[must_use]
    pub(crate) fn verify(&self, record_domain: &str, canonical: &[u8], tag: &[u8]) -> bool {
        if tag.len() != INTEGRITY_TAG_BYTES {
            return false;
        }
        let Ok(mut expected) = self.tag(record_domain, canonical) else {
            return false;
        };
        let matches = constant_time_eq(&expected, tag);
        scrub_secret(&mut expected);
        matches
    }
}

fn validate_integrity_key_bytes(bytes: &mut [u8]) -> Result<(), TransactionStoreError> {
    if bytes.len() != INTEGRITY_KEY_BYTES || bytes.iter().all(|byte| *byte == 0) {
        scrub_secret(bytes);
        return Err(TransactionStoreError::AuthorityRejected);
    }
    Ok(())
}

/// Overwrite secret-bearing storage through atomic stores so the writes remain
/// observable to the compiler and cannot be removed as dead stores before the
/// allocation is released.
fn scrub_secret(bytes: &mut [u8]) {
    for byte in bytes {
        AtomicU8::from_mut(byte).store(0, Ordering::SeqCst);
    }
}

fn hmac_sha256<'a>(
    inner_pad: &[u8; SHA256_BLOCK_BYTES],
    outer_pad: &[u8; SHA256_BLOCK_BYTES],
    fields: impl IntoIterator<Item = &'a [u8]>,
) -> [u8; INTEGRITY_TAG_BYTES] {
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    for field in fields {
        inner.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        inner.update(field);
    }
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();

    let mut tag = [0_u8; INTEGRITY_TAG_BYTES];
    tag.copy_from_slice(&digest);
    tag
}

fn constant_time_eq(expected: &[u8; INTEGRITY_TAG_BYTES], actual: &[u8]) -> bool {
    let mut difference = 0_u8;
    for (left, right) in expected.iter().zip(actual.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

pub(crate) fn canonical_field(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    buffer.extend_from_slice(bytes);
}

pub(crate) fn canonical_optional(buffer: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            canonical_field(buffer, &[1]);
            canonical_field(buffer, value.as_bytes());
        }
        None => canonical_field(buffer, &[0]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_owned_pads_preserve_persisted_hmac_and_fingerprint() {
        // Independent Python stdlib hmac/hashlib vectors over the unchanged
        // three u64-length-prefixed fields; this is public fixture material.
        let key = SqliteIntegrityKey::new(vec![0x0b; 32])
            .unwrap_or_else(|error| unreachable!("{error}"));
        assert_eq!(key.fingerprint().hex(), "54f318f0310adb92cba0f507d9ec9aaa09612a6d79f47b6951281e413f7a7e82");
        for (domain, canonical, expected) in [
            ("linura.sqlite.test.v1", b"".as_slice(), "ccae577be5a0fbff0c3f09bdbd4ed0fd39cd0982819e30cd1a8bcf3682801a7d"),
            ("linura.sqlite.test.v1", b"persisted-record".as_slice(), "947f33e7d51e0c126fc6c6b423217120d59cc39e2bd07ffea605fa143dc4f48e"),
            ("linura.sqlite.test.v2", b"persisted-record".as_slice(), "af333c42a1598e57e96f11b048c008a96f4d6dee34caa7fcd70e8593d1fb46bb"),
        ] {
            let tag = key.tag(domain, canonical).unwrap_or_else(|error| unreachable!("{error}"));
            let hex: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, expected);
            assert!(key.verify(domain, canonical, &tag));
            assert!(!key.verify("foreign", canonical, &tag));
            assert!(!key.verify(domain, canonical, &tag[..31]));
            let mut altered = tag;
            altered[0] ^= 1;
            assert!(!key.verify(domain, canonical, &altered));
        }
    }

    #[test]
    fn key_destruction_scrubs_original_and_derived_key_material() {
        let mut key = SqliteIntegrityKey::new(vec![0x0b; 32])
            .unwrap_or_else(|error| unreachable!("{error}"));
        key.scrub();
        assert!(key.bytes.iter().all(|byte| *byte == 0));
        assert!(key.pads.iter().flatten().all(|byte| *byte == 0));
    }

    #[test]
    fn rejected_integrity_key_material_is_scrubbed_before_error_returns() {
        let mut rejected = vec![0x5a; INTEGRITY_KEY_BYTES - 1];
        assert_eq!(
            validate_integrity_key_bytes(&mut rejected),
            Err(TransactionStoreError::AuthorityRejected)
        );
        assert!(rejected.iter().all(|byte| *byte == 0));
    }
}
