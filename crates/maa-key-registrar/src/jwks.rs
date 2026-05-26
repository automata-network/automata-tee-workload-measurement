//! Fetch and parse a Microsoft Azure Attestation JWKS (`/certs`).
//!
//! MAA exposes its signing keys at `<endpoint>/certs` as a flat JWK Set. Each
//! entry has:
//!   - `kid` — string identifier hashed (keccak256) for on-chain lookup.
//!   - `x5c[]` — base64-encoded X.509 cert chain. `x5c[0]` is the leaf cert
//!     whose Subject Public Key is the RSA-2048 signing key and whose
//!     NotAfter is the on-chain `notAfter` (Unix seconds).
//!
//! MAA also includes the JWK `n`/`e` fields; we ignore them and parse `x5c[0]`
//! so we can capture `notAfter` from the same source.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
pub struct Jwk {
    pub kid: String,
    #[serde(default)]
    pub x5c: Vec<String>,
}

/// Fetch the JWK Set at `<endpoint>/certs`. Validates basic shape (non-empty
/// `keys`, every entry has a non-empty `kid` + `x5c`).
pub async fn fetch_jwks(endpoint: &str) -> Result<JwkSet> {
    let url = format!("{}/certs", endpoint.trim_end_matches('/'));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("building HTTP client")?;

    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("MAA JWKS fetch failed: HTTP {status} — body: {body}");
    }

    let jwks: JwkSet = resp
        .json()
        .await
        .with_context(|| format!("parsing JWKS from {url}"))?;

    if jwks.keys.is_empty() {
        bail!("MAA JWKS at {url} returned an empty key set");
    }
    for (i, key) in jwks.keys.iter().enumerate() {
        if key.kid.is_empty() {
            bail!("MAA JWKS at {url}: keys[{i}].kid is empty");
        }
        if key.x5c.is_empty() {
            bail!(
                "MAA JWKS at {url}: keys[{i}] (kid={}) has no x5c chain; \
                 cannot derive pkcs1Pubkey + notAfter without it",
                key.kid
            );
        }
    }

    Ok(jwks)
}
