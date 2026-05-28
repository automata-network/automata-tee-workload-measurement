//! Off-chain registrar for the on-chain `MaaKeyRegistry`.
//!
//! Subcommands:
//!   - `derive`  — fetch JWKS, print the four upsert args for every kid.
//!   - `status`  — diff JWKS vs the on-chain registry; flag missing / drifted / expiring kids.
//!   - `sync`    — broadcast `upsertMaaSigningKey` for every JWKS kid not already
//!                 current on chain. `--dry-run` prints `cast send` lines instead.
//!   - `revoke`  — broadcast `revokeMaaSigningKey` for one kid.

mod cert;
mod chain;
mod derive;
mod jwks;

use std::str::FromStr;

use alloy::primitives::{Address, keccak256};
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use tracing::{info, warn};

use crate::chain::MaaKeyRegistryClient;
use crate::derive::{Include, UpsertParams, derive_all};

/// Default MAA endpoint — matches the portal's hard-coded `AZURE_MAA_REGION_DEFAULT = "eus"`.
const DEFAULT_ENDPOINT: &str = "https://sharedeus.eus.attest.azure.net";

/// Refuse to call upsert when notAfter is within this window of "now"; the
/// new cert is supposed to overlap an old one for ~2 months, so a same-day
/// expiry strongly suggests stale JWKS or a clock skew.
const MIN_VALIDITY_SECS: u64 = 86_400;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Increase log level.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Fetch JWKS and print derived upsert args. No on-chain reads.
    Derive(DeriveArgs),
    /// Diff JWKS vs on-chain registry state.
    Status(StatusArgs),
    /// Upsert any JWKS kid not currently registered on chain.
    Sync(SyncArgs),
    /// Revoke a specific kid on chain.
    Revoke(RevokeArgs),
}

#[derive(Args)]
struct EndpointArgs {
    /// MAA endpoint URL (no trailing slash). Default `sharedeus.eus.attest.azure.net`.
    #[arg(long, default_value = DEFAULT_ENDPOINT)]
    endpoint: String,

    /// JWT `iss` claim value to commit on chain. MAA shared pools emit the
    /// endpoint URL itself; custom tenants may differ. When unsure, attest
    /// once and copy the literal `iss` claim from the resulting JWT.
    #[arg(long)]
    iss: Option<String>,

    /// Which JWKS entries to consider for upsert. Default `self-signed`
    /// matches what MAA shared pools actually sign attestation JWTs with;
    /// the chained Microsoft-PKI cert in JWKS is tenant-mode-only and
    /// registering it grants signing trust to a key the shared pool never
    /// emits JWTs under. Use `any` for tenant-mode endpoints.
    #[arg(long, value_enum, default_value_t = Include::SelfSigned)]
    include: Include,
}

impl EndpointArgs {
    fn iss(&self) -> String {
        self.iss.clone().unwrap_or_else(|| self.endpoint.clone())
    }
}

#[derive(Args)]
struct ChainArgs {
    /// Ethereum JSON-RPC URL.
    #[arg(long)]
    rpc: String,
    /// MaaKeyRegistry proxy address (0x…).
    #[arg(long)]
    registry: Address,
}

#[derive(Args)]
struct SignerArgs {
    /// Owner private key. Accepts a raw hex literal (`0x…`),
    /// a path to a file containing the hex literal, or the value of
    /// `$ATAKIT_MAA_OWNER_KEY` (read implicitly when no value is given).
    #[arg(long, env = "ATAKIT_MAA_OWNER_KEY")]
    owner_key: String,
}

impl SignerArgs {
    fn signer(&self) -> Result<PrivateKeySigner> {
        let raw = if std::path::Path::new(&self.owner_key).is_file() {
            std::fs::read_to_string(&self.owner_key)
                .with_context(|| format!("reading owner key from {}", self.owner_key))?
        } else {
            self.owner_key.clone()
        };
        PrivateKeySigner::from_str(raw.trim()).context("parsing owner key")
    }
}

#[derive(Args)]
struct DeriveArgs {
    #[command(flatten)]
    endpoint: EndpointArgs,
    /// Emit a JSON array instead of human-formatted text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct StatusArgs {
    #[command(flatten)]
    endpoint: EndpointArgs,
    #[command(flatten)]
    chain: ChainArgs,
}

#[derive(Args)]
struct SyncArgs {
    #[command(flatten)]
    endpoint: EndpointArgs,
    #[command(flatten)]
    chain: ChainArgs,
    #[command(flatten)]
    signer: SignerArgs,
    /// Print `cast send` commands instead of broadcasting.
    #[arg(long)]
    dry_run: bool,
    /// Skip the y/N prompt before broadcasting.
    #[arg(short, long)]
    yes: bool,
    /// Re-upsert kids that are already current. Default: skip them.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct RevokeArgs {
    /// The JWT header `kid` string (NOT the keccak256 hash).
    #[arg(long)]
    kid: String,
    #[command(flatten)]
    chain: ChainArgs,
    #[command(flatten)]
    signer: SignerArgs,
    /// Print the `cast send` command instead of broadcasting.
    #[arg(long)]
    dry_run: bool,
    /// Skip the y/N prompt before broadcasting.
    #[arg(short, long)]
    yes: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .init();

    match cli.cmd {
        Cmd::Derive(args) => run_derive(args).await,
        Cmd::Status(args) => run_status(args).await,
        Cmd::Sync(args) => run_sync(args).await,
        Cmd::Revoke(args) => run_revoke(args).await,
    }
}

async fn run_derive(args: DeriveArgs) -> Result<()> {
    let jwks = jwks::fetch_jwks(&args.endpoint.endpoint).await?;
    let iss = args.endpoint.iss();
    let params = derive_all(&jwks, &iss, args.endpoint.include)?;

    if args.json {
        let json: Vec<_> = params.iter().map(param_to_json).collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }

    println!("MAA endpoint   : {}", args.endpoint.endpoint);
    println!("Filter         : {:?}", args.endpoint.include);
    println!("Assumed iss    : {iss}");
    println!("issuerHash     : {:#x}", keccak256(iss.as_bytes()));
    println!(
        "Keys           : {} (filtered from {} in JWKS)",
        params.len(),
        jwks.keys.len()
    );
    println!();
    for (i, p) in params.iter().enumerate() {
        print_param_block(i, p);
    }
    Ok(())
}

async fn run_status(args: StatusArgs) -> Result<()> {
    let jwks = jwks::fetch_jwks(&args.endpoint.endpoint).await?;
    let iss = args.endpoint.iss();
    let params = derive_all(&jwks, &iss, args.endpoint.include)?;

    let client = MaaKeyRegistryClient::read_only(&args.chain.rpc, args.chain.registry).await?;
    let now = unix_now();

    let mut current = 0u32;
    let mut missing = 0u32;
    let mut drifted = 0u32;
    let mut expiring = 0u32;

    for p in &params {
        match classify(&client, p, now).await? {
            KidState::Current => current += 1,
            KidState::Missing => missing += 1,
            KidState::Drifted(_) => drifted += 1,
            KidState::ExpiringSoon => expiring += 1,
        }
    }

    println!("MAA endpoint   : {}", args.endpoint.endpoint);
    println!("Registry       : {:#x}", args.chain.registry);
    println!("Keys in JWKS   : {}", params.len());
    println!("  current      : {current}");
    println!("  missing      : {missing}");
    println!("  drifted      : {drifted}");
    println!("  expiring <30d: {expiring}");
    println!();

    for p in &params {
        let state = classify(&client, p, now).await?;
        print_status_line(p, &state, now);
    }
    Ok(())
}

async fn run_sync(args: SyncArgs) -> Result<()> {
    let jwks = jwks::fetch_jwks(&args.endpoint.endpoint).await?;
    let iss = args.endpoint.iss();
    let params = derive_all(&jwks, &iss, args.endpoint.include)?;

    let now = unix_now();

    // Sanity: notAfter must be at least MIN_VALIDITY_SECS in the future.
    for p in &params {
        if p.not_after < now + MIN_VALIDITY_SECS {
            warn!(
                kid = %p.kid,
                not_after = p.not_after,
                "JWKS kid has notAfter within {} seconds — refusing to upsert. \
                 Investigate JWKS / clock drift.",
                MIN_VALIDITY_SECS
            );
            bail!("aborting sync: stale notAfter on kid {}", p.kid);
        }
    }

    // Decide which kids need work.
    let read_client =
        MaaKeyRegistryClient::read_only(&args.chain.rpc, args.chain.registry).await?;
    let mut to_upsert: Vec<&UpsertParams> = Vec::new();
    for p in &params {
        let state = classify(&read_client, p, now).await?;
        let needs = matches!(
            state,
            KidState::Missing | KidState::Drifted(_) | KidState::ExpiringSoon
        ) || args.force;
        if needs {
            to_upsert.push(p);
        }
    }

    if to_upsert.is_empty() {
        println!("Nothing to do — every JWKS kid is current on chain.");
        return Ok(());
    }

    println!("Plan: upsert {} kid(s) on {:#x}", to_upsert.len(), args.chain.registry);
    for p in &to_upsert {
        println!("  - {} (notAfter {})", p.kid, p.not_after);
    }

    if args.dry_run {
        println!();
        for p in &to_upsert {
            println!("{}", cast_send_upsert(args.chain.registry, p));
        }
        return Ok(());
    }

    if !args.yes && !confirm("Proceed?")? {
        println!("Aborted.");
        return Ok(());
    }

    let signer = args.signer.signer()?;
    let write_client =
        MaaKeyRegistryClient::with_signer(&args.chain.rpc, args.chain.registry, signer).await?;

    for p in to_upsert {
        info!(kid = %p.kid, kid_hash = %p.kid_hash, "upserting");
        let tx_hash = write_client
            .upsert(
                p.kid_hash,
                p.pkcs1_pubkey.clone(),
                p.issuer_hash,
                p.not_after,
            )
            .await?;
        println!("upserted {} → tx {:#x}", p.kid, tx_hash);
    }
    Ok(())
}

async fn run_revoke(args: RevokeArgs) -> Result<()> {
    let kid_hash = keccak256(args.kid.as_bytes());
    println!("kid        : {}", args.kid);
    println!("kidHash    : {kid_hash:#x}");
    println!("registry   : {:#x}", args.chain.registry);

    if args.dry_run {
        println!();
        println!(
            "cast send {:#x} 'revokeMaaSigningKey(bytes32)' {:#x} --rpc-url {}",
            args.chain.registry, kid_hash, args.chain.rpc
        );
        return Ok(());
    }

    if !args.yes && !confirm("Revoke this kid?")? {
        println!("Aborted.");
        return Ok(());
    }

    let signer = args.signer.signer()?;
    let client =
        MaaKeyRegistryClient::with_signer(&args.chain.rpc, args.chain.registry, signer).await?;
    let tx_hash = client.revoke(kid_hash).await?;
    println!("revoked → tx {tx_hash:#x}");
    Ok(())
}

// ── helpers ────────────────────────────────────────────────────────────────

enum KidState {
    Current,
    Missing,
    /// Registered, but at least one of (pkcs1Pubkey, issuerHash, notAfter)
    /// disagrees with what JWKS currently advertises.
    Drifted(&'static str),
    /// Registered + current bytes, but `notAfter` is within the configured
    /// rotation-warning window (30 days).
    ExpiringSoon,
}

const EXPIRING_SOON_WINDOW: u64 = 30 * 86_400;

async fn classify(
    client: &MaaKeyRegistryClient,
    p: &UpsertParams,
    now: u64,
) -> Result<KidState> {
    if !client.has_kid(p.kid_hash).await? {
        return Ok(KidState::Missing);
    }
    let on_chain = client.get_key(p.kid_hash).await?;
    if on_chain.pkcs1Pubkey.as_ref() != p.pkcs1_pubkey.as_ref() {
        return Ok(KidState::Drifted("pkcs1Pubkey"));
    }
    if on_chain.issuerHash != p.issuer_hash {
        return Ok(KidState::Drifted("issuerHash"));
    }
    if on_chain.notAfter != p.not_after {
        return Ok(KidState::Drifted("notAfter"));
    }
    if p.not_after.saturating_sub(now) < EXPIRING_SOON_WINDOW {
        return Ok(KidState::ExpiringSoon);
    }
    Ok(KidState::Current)
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

fn cast_send_upsert(registry: Address, p: &UpsertParams) -> String {
    format!(
        "cast send {:#x} \
         'upsertMaaSigningKey(bytes32,bytes,bytes32,uint64)' \
         {:#x} \
         0x{} \
         {:#x} \
         {}",
        registry,
        p.kid_hash,
        hex::encode(p.pkcs1_pubkey.as_ref()),
        p.issuer_hash,
        p.not_after,
    )
}

fn param_to_json(p: &UpsertParams) -> serde_json::Value {
    serde_json::json!({
        "kid": p.kid,
        "kidHash": format!("{:#x}", p.kid_hash),
        "pkcs1Pubkey": format!("0x{}", hex::encode(p.pkcs1_pubkey.as_ref())),
        "issuerHash": format!("{:#x}", p.issuer_hash),
        "notAfter": p.not_after,
        "selfSigned": p.is_self_signed,
        "rsaBits": p.rsa_bits,
    })
}

fn print_param_block(i: usize, p: &UpsertParams) {
    let selfsign = if p.is_self_signed { "self-signed" } else { "chained" };
    println!("[{i}] kid          : {}", p.kid);
    println!("    cert         : {selfsign}, RSA-{}", p.rsa_bits);
    println!("    kidHash      : {:#x}", p.kid_hash);
    println!(
        "    pkcs1Pubkey  : 0x{} ({} bytes)",
        hex::encode(p.pkcs1_pubkey.as_ref()),
        p.pkcs1_pubkey.len()
    );
    println!("    issuerHash   : {:#x}", p.issuer_hash);
    println!("    notAfter     : {}", p.not_after);
    println!();
}

fn print_status_line(p: &UpsertParams, state: &KidState, now: u64) {
    let days_left = (p.not_after as i64 - now as i64) / 86_400;
    let tag = match state {
        KidState::Current => "current".to_string(),
        KidState::Missing => "MISSING".to_string(),
        KidState::Drifted(field) => format!("DRIFTED ({field})"),
        KidState::ExpiringSoon => "expiring".to_string(),
    };
    println!("  [{tag:<18}] kid={}  notAfter=+{days_left}d", p.kid);
}

fn confirm(prompt: &str) -> Result<bool> {
    use std::io::{BufRead, Write};
    print!("{prompt} [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let ans = line.trim().to_ascii_lowercase();
    Ok(ans == "y" || ans == "yes")
}
