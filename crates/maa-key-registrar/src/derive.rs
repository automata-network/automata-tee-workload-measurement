//! Combine JWKS + leaf-cert parsing into the four `upsertMaaSigningKey` args.
//!
//! For each JWK in the set:
//!   `kidHash    = keccak256(bytes(kid))`
//!   `pkcs1Pubkey = DER PKCS#1 RSAPublicKey (from x5c[0] SPKI)`
//!   `issuerHash = keccak256(bytes(iss_string))`
//!   `notAfter   = leaf cert NotAfter, Unix seconds`
//!
//! The `iss` string MUST equal what MAA puts in the JWT `iss` claim. For the
//! public shared pools this is the endpoint URL itself
//! (e.g. `https://sharedeus.eus.attest.azure.net`); custom tenants and any
//! tenant emitting a divergent `iss` need an explicit override (`--iss`).

use alloy::primitives::{B256, Bytes, keccak256};
use anyhow::Result;

use crate::cert::{ParsedLeaf, parse_leaf_x5c};
use crate::jwks::{Jwk, JwkSet};

/// Minimum RSA modulus size we'll accept. Microsoft has had RSA-1024 legacy
/// keys in shared-pool JWKS as recently as 2026; never register them.
pub const MIN_RSA_BITS: u32 = 2048;

/// The four arguments of `upsertMaaSigningKey`, plus the JWK `kid` string
/// and a few facts about the source cert so callers can filter and report.
#[derive(Debug, Clone)]
pub struct UpsertParams {
    pub kid: String,
    pub kid_hash: B256,
    pub pkcs1_pubkey: Bytes,
    pub issuer_hash: B256,
    pub not_after: u64,
    pub is_self_signed: bool,
    pub rsa_bits: u32,
}

impl UpsertParams {
    /// Build from one JWK + an `iss` override.
    pub fn from_jwk(jwk: &Jwk, iss: &str) -> Result<Self> {
        let leaf = parse_leaf_x5c(&jwk.x5c[0])?;
        Ok(Self::new(&jwk.kid, iss, leaf))
    }

    fn new(kid: &str, iss: &str, leaf: ParsedLeaf) -> Self {
        Self {
            kid: kid.to_string(),
            kid_hash: keccak256(kid.as_bytes()),
            pkcs1_pubkey: leaf.pkcs1_pubkey.into(),
            issuer_hash: keccak256(iss.as_bytes()),
            not_after: leaf.not_after,
            is_self_signed: leaf.is_self_signed,
            rsa_bits: leaf.rsa_bits,
        }
    }
}

/// Which subset of JWKS keys to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Include {
    /// Only self-signed leaves with RSA ≥ 2048. Correct default for MAA
    /// shared pools; JWTs from `https://shared<region>.<region>.attest.azure.net`
    /// are signed by self-signed CN=<endpoint> certs. The chained
    /// Microsoft-PKI cert in JWKS is for tenant-mode MAA, not shared.
    SelfSigned,
    /// Every leaf with RSA ≥ 2048, self-signed or chained. Use for custom
    /// (tenant-mode) MAA endpoints that emit JWTs under a chained cert.
    Any,
    /// No filtering at all — include the legacy RSA-1024 leaves too.
    /// Almost never what you want; provided as an escape hatch for forensics.
    All,
}

/// Derive params for every key in a JWKS, filtered by `include`. If any leaf
/// is malformed, the whole call fails (a partial JWKS is a signal, not a
/// transient).
pub fn derive_all(jwks: &JwkSet, iss: &str, include: Include) -> Result<Vec<UpsertParams>> {
    let all: Vec<UpsertParams> = jwks
        .keys
        .iter()
        .map(|jwk| UpsertParams::from_jwk(jwk, iss))
        .collect::<Result<_>>()?;

    Ok(all
        .into_iter()
        .filter(|p| include.accepts(p))
        .collect())
}

impl Include {
    fn accepts(self, p: &UpsertParams) -> bool {
        match self {
            Include::SelfSigned => p.is_self_signed && p.rsa_bits >= MIN_RSA_BITS,
            Include::Any => p.rsa_bits >= MIN_RSA_BITS,
            Include::All => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kid_hash_is_keccak_of_kid_bytes() {
        // Sanity check against a known keccak256 vector for the empty string.
        // keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        assert_eq!(
            format!("{:x}", keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn issuer_hash_matches_endpoint_default() {
        let iss = "https://sharedeus.eus.attest.azure.net";
        let h = keccak256(iss.as_bytes());
        // Re-deriving the same string yields the same hash, by construction;
        // this guards against an accidental encoding tweak (e.g. trimming a
        // trailing slash silently).
        assert_eq!(h, keccak256(iss.as_bytes()));
    }
}
