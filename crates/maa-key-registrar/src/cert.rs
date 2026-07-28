//! Parse a base64-encoded X.509 leaf certificate (from JWK `x5c[0]`) into
//! the two pieces the on-chain registry needs:
//!
//! 1. `pkcs1Pubkey` — DER PKCS#1 `RSAPublicKey` (SEQUENCE { INTEGER n, INTEGER e }).
//!    The X.509 `SubjectPublicKeyInfo` wraps this in an AlgorithmIdentifier
//!    + BIT STRING; for the `rsaEncryption` OID (1.2.840.113549.1.1.1) the
//!      BIT STRING contents are the PKCS#1 `RSAPublicKey` directly.
//! 2. `notAfter` — Unix seconds from the leaf cert's validity window.

use anyhow::{Context, Result, bail};
use base64::Engine;
use x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION;
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub struct ParsedLeaf {
    /// DER PKCS#1 RSAPublicKey (~270 bytes for RSA-2048).
    pub pkcs1_pubkey: Vec<u8>,
    /// Unix seconds.
    pub not_after: u64,
    /// `true` when `subject == issuer` byte-for-byte. The MAA shared pools
    /// sign JWTs with self-signed certs whose `CN` is the endpoint URL;
    /// chained Microsoft-PKI certs in JWKS are used by tenant-mode MAA, not
    /// by the shared pool, and registering them grants signing trust to keys
    /// the shared pool will not actually emit JWTs under.
    pub is_self_signed: bool,
    /// RSA modulus bit-length (e.g. 2048). Approximated from the PKCS#1
    /// SEQUENCE length; sufficient for "reject < 2048".
    pub rsa_bits: u32,
}

/// Decode + parse a single `x5c[0]` base64 string. Verifies the public-key
/// algorithm is RSA and rejects non-RSA keys early (MAA only signs with RSA).
pub fn parse_leaf_x5c(x5c_b64: &str) -> Result<ParsedLeaf> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(x5c_b64.trim())
        .context("base64-decoding x5c[0]")?;

    let (_, cert) = X509Certificate::from_der(&der).context("parsing X.509 DER from x5c[0]")?;

    // ── Algorithm must be RSA ──────────────────────────────────────────
    let spki = cert.public_key();
    if spki.algorithm.algorithm != OID_PKCS1_RSAENCRYPTION {
        bail!(
            "leaf cert SubjectPublicKeyInfo algorithm is {} (expected rsaEncryption {})",
            spki.algorithm.algorithm,
            OID_PKCS1_RSAENCRYPTION
        );
    }

    // ── Extract PKCS#1 RSAPublicKey from the BIT STRING contents ────────
    // For rsaEncryption, the SPKI's BIT STRING payload IS the DER
    // SEQUENCE { INTEGER n, INTEGER e } — no further unwrapping needed.
    let pkcs1_pubkey = spki.subject_public_key.data.to_vec();
    if pkcs1_pubkey.is_empty() {
        bail!("leaf cert SubjectPublicKey BIT STRING is empty");
    }

    // ── Validity.notAfter as Unix seconds ───────────────────────────────
    let not_after = cert
        .validity()
        .not_after
        .timestamp()
        .try_into()
        .context("notAfter is before the Unix epoch")?;

    // ── subject == issuer (DER-encoded) ────────────────────────────────
    let is_self_signed = cert.subject().as_raw() == cert.issuer().as_raw();

    // ── RSA modulus bit length ─────────────────────────────────────────
    // Cheap structural extraction: PKCS#1 RSAPublicKey is
    //   SEQUENCE { INTEGER n, INTEGER e }
    // We read the inner INTEGER n's length tag and bit-extend. Sufficient
    // for "reject keys shorter than 2048 bits"; we don't need exact bits.
    let rsa_bits = rsa_modulus_bits(&pkcs1_pubkey).unwrap_or(0);

    Ok(ParsedLeaf {
        pkcs1_pubkey,
        not_after,
        is_self_signed,
        rsa_bits,
    })
}

/// Best-effort RSA modulus bit-length extraction from a DER
/// `SEQUENCE { INTEGER n, INTEGER e }`. Returns `None` if the structure
/// looks wrong; callers should treat that as "unknown size" and warn.
fn rsa_modulus_bits(pkcs1_der: &[u8]) -> Option<u32> {
    // SEQUENCE tag (0x30), length (1-3 bytes), then INTEGER (0x02), length, value.
    let mut i = 0;
    if *pkcs1_der.first()? != 0x30 {
        return None;
    }
    i += 1;
    i += der_skip_length(pkcs1_der, i)?;
    if *pkcs1_der.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let (n_len, len_bytes) = der_read_length(pkcs1_der, i)?;
    i += len_bytes;
    // The INTEGER value may be preceded by a 0x00 sign byte; strip it for
    // the bit count.
    let mut effective = n_len;
    if pkcs1_der.get(i).copied() == Some(0x00) {
        effective = effective.saturating_sub(1);
    }
    Some((effective as u32) * 8)
}

fn der_skip_length(buf: &[u8], pos: usize) -> Option<usize> {
    let (_, n) = der_read_length(buf, pos)?;
    Some(n)
}

/// Returns (length_value, bytes_consumed_for_the_length_field).
fn der_read_length(buf: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *buf.get(pos)?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    let n_octets = (first & 0x7f) as usize;
    if n_octets == 0 || n_octets > 4 {
        return None;
    }
    let mut len = 0usize;
    for j in 0..n_octets {
        len = (len << 8) | (*buf.get(pos + 1 + j)? as usize);
    }
    Some((len, 1 + n_octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal smoke test: a real MAA leaf (truncated stand-in would require
    // committing PII-free static data). For now we only assert the
    // happy-path types compile and the function rejects garbage.
    #[test]
    fn parse_leaf_rejects_garbage() {
        let err = parse_leaf_x5c("not base64!").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("base64") || msg.contains("DER"), "{msg}");
    }
}
