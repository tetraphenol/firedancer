# Firedancer vs. Frankendancer - Architecture and Build Configuration

**Analysis Date:** November 11, 2025
**Purpose:** Understanding the delineation between Firedancer and Frankendancer implementations

---

## **High-Level Distinction**

### **Frankendancer** (Current Release - v0.x)
A **hybrid validator** that combines:
- **Firedancer components**: High-performance networking, signature verification, and block production
- **Agave components**: Transaction execution (sBPF VM), consensus, and runtime

### **Firedancer** (Future - v1.x)
A **fully independent validator** with:
- All components implemented in C from scratch
- No Agave dependency
- Currently under development, not production-ready

---

## **Tile Distribution by Implementation**

Looking at [src/app/fdctl/topology.c:147-156](../src/app/fdctl/topology.c#L147-L156), each tile has an `is_agave` flag indicating which implementation handles it:

### **Firedancer Tiles** (`is_agave = 0`)
These tiles are implemented in C and run as separate processes:

| Tile | Purpose | Source Location |
|------|---------|-----------------|
| **net** | Raw packet I/O via AF_XDP | `src/disco/net/` |
| **quic** | QUIC protocol, TLS 1.3 decryption, packet reassembly | `src/disco/quic/` |
| **verify** | ED25519 signature verification (AVX-512 accelerated) | `src/disco/verify/` |
| **dedup** | Duplicate transaction filtering via signature cache | `src/disco/dedup/` |
| **pack** | Transaction scheduling, block packing | `src/disco/pack/` |
| **shred** | Block distribution (FEC encoding, Turbine protocol) | `src/disco/shred/` |
| **sign** | Transaction signing | `src/disco/sign/` |
| **metric** | Metrics collection | `src/disco/metric/` |
| **cswtch** | Context switching/coordination | `src/disco/cswtch/` |

### **Agave Tiles** (`is_agave = 1`)
These components are still handled by the Agave validator (Rust code):

| Tile | Purpose | Implementation |
|------|---------|----------------|
| **resolv** | Address resolution for transactions | Agave |
| **bank** | Transaction execution, account state management | Agave |
| **poh** | Proof of History generation | Agave |
| **store** | Block storage to disk (RocksDB) | Agave |

---

## **Build System**

### **Building Frankendancer (Hybrid)**

```bash
# This builds fdctl (Frankendancer) + Agave components
make -j fdctl solana
```

**What this does:**
1. Compiles Firedancer tiles (C code in `src/disco/`, `src/waltz/`, etc.)
2. Invokes `cargo build` to compile Agave validator library
3. Links Firedancer binary `fdctl` with `libagave_validator.a`
4. Produces `build/native/gcc/bin/fdctl` and `build/native/gcc/bin/solana`

**Key build files:**
- [src/app/fdctl/Local.mk](../src/app/fdctl/Local.mk) - Defines `fdctl` build with Agave linking
- Line 42: `make-bin-rust,fdctl,main,...,agave_validator,...` - Links Agave library
- Lines 62-113: Cargo build rules for `agave-validator` Rust crate

### **Building Pure Firedancer (Future)**

```bash
# This builds the pure C validator (not production-ready)
make -j firedancer
```

**What this does:**
1. Compiles all Firedancer components in C
2. Does NOT invoke Agave/Rust build
3. Produces `build/native/gcc/bin/firedancer`

**Key build files:**
- [src/app/firedancer/Local.mk](../src/app/firedancer/Local.mk) - Defines pure Firedancer build
- Line 50: `make-bin,firedancer,main,...` - No Agave dependency
- Includes additional Firedancer-only components from `src/discof/` and `src/choreo/`

---

## **Process Architecture at Runtime**

When you run Frankendancer (`fdctl run`), you get this process tree (from [book/guide/getting-started.md:299-322](../book/guide/getting-started.md#L299-L322)):

```
fdctl run --config ~/config.toml
 └─fdctl run --config ~/config.toml
     └─fdctl run --config ~/config.toml
         ├─fdctl run-agave --config-fd 0     ← Agave validator (Rust)
         │   └─35*[{fdctl}]                    (multi-threaded)
         ├─net:0 run1 net 0                  ← Firedancer tile
         ├─quic:0 run1 quic 0                ← Firedancer tile
         ├─verify:0 run1 verify 0            ← Firedancer tile
         ├─verify:1 run1 verify 1            ← (6 verify tiles)
         ├─verify:2 run1 verify 2
         ├─verify:3 run1 verify 3
         ├─verify:4 run1 verify 4
         ├─verify:5 run1 verify 5
         ├─dedup:0 run1 dedup 0              ← Firedancer tile
         ├─pack:0 run1 pack 0                ← Firedancer tile
         ├─shred:0 run1 shred 0              ← Firedancer tile
         ├─sign:0 run1 sign 0                ← Firedancer tile
         ├─metric:0 run1 metric 0            ← Firedancer tile
         └─cswtch:0 run1 cswtch 0            ← Firedancer tile
```

**Communication:** Firedancer tiles communicate with Agave via **shared memory** (Tango IPC + Funk transactional KV store).

---

## **Data Flow Architecture**

### **Frankendancer Pipeline**

```
External Network
     ↓
┌─────────────────────────────────────────┐
│         FIREDANCER TILES (C)            │
│                                         │
│  NET → QUIC → VERIFY → DEDUP → PACK    │
│   ↓      ↓       ↓        ↓       ↓    │
│  XDP   TLS1.3  ED25519  Sig     Block  │
│        decrypt  verify  cache   packing │
└─────────────────────────────────────────┘
              ↓ Shared Memory (Tango)
┌─────────────────────────────────────────┐
│          AGAVE TILES (Rust)             │
│                                         │
│  BANK → POH → SHRED → STORE            │
│   ↓      ↓      ↓       ↓               │
│  sBPF   Hash  Turbine  RocksDB         │
│   VM   mixing protocol                  │
└─────────────────────────────────────────┘
              ↓
         Disk Storage
```

### **Pure Firedancer Pipeline (Future)**

```
External Network
     ↓
┌─────────────────────────────────────────┐
│       ALL TILES IMPLEMENTED IN C        │
│                                         │
│  NET → QUIC → VERIFY → DEDUP → PACK    │
│                          ↓               │
│  GOSSIP → REPLAY → BANK → POH → SHRED  │
│     ↓       ↓       ↓      ↓       ↓    │
│  Crds   Forkchoice sBPF  Hash  Turbine │
│  cache   (Ghost)   VM   mixing protocol│
│                                         │
│  TOWER (consensus/voting)               │
└─────────────────────────────────────────┘
              ↓
         Disk Storage
```

---

## **Configuration**

The configuration file controls Frankendancer-specific settings under the `[frankendancer]` section. This doesn't exist in pure Firedancer builds.

From [src/app/fdctl/config/default.toml](../src/app/fdctl/config/default.toml):
- `dynamic_port_range` - Ports for Agave components
- `consensus.*` - Consensus parameters passed to Agave
- `layout.agave_affinity` - CPU pinning for Agave tiles

---

## **Key Differences in Code**

### **Topology Files**
- [src/app/fdctl/topology.c](../src/app/fdctl/topology.c) - Frankendancer topology (hybrid)
  - Defines tiles with `is_agave` flag
  - Sets up shared memory workspaces for IPC
  - Example: Line 151: `fd_topob_tile( topo, "resolv", ..., 1, 0 )` - `is_agave=1`

- [src/app/firedancer/topology.c](../src/app/firedancer/topology.c) - Pure Firedancer topology
  - All tiles implemented in C
  - Includes additional tiles: `gossip`, `replay`, `tower`, `repair`, `snapct`
  - No Agave integration

### **Agave Integration Code**
- [src/app/fdctl/commands/run_agave.c](../src/app/fdctl/commands/run_agave.c) - Spawns Agave validator as child process
  - Function `agave_boot()` (line 53): Constructs command-line arguments for Agave validator
  - Function `clone_labs_memory_space_tiles()` (line 22): Maps shared memory for Agave tiles
  - Calls `fd_ext_validator_main()` to launch Agave's Rust code

### **Additional Firedancer Components (Pure C)**

These are only present in pure Firedancer builds:

| Component | Location | Purpose |
|-----------|----------|---------|
| **Gossip** | `src/discof/gossip/` | Peer discovery, cluster membership |
| **Replay** | `src/discof/replay/` | Block replay, fork validation |
| **Tower** | `src/discof/tower/` | Tower BFT consensus voting |
| **Ghost** | `src/choreo/ghost/` | Heaviest fork choice algorithm |
| **Repair** | `src/discof/repair/` | Missing block/shred repair protocol |
| **Snapct** | `src/discof/restore/` | Snapshot creation and restoration |

---

## **Build Targets Reference**

### **Make Targets**

```bash
# Frankendancer (hybrid)
make -j fdctl solana          # Full Frankendancer + CLI tools
make -j fdctl                 # Just Frankendancer binary

# Pure Firedancer (not production-ready)
make -j firedancer            # Pure C validator

# Development
make -j fddev                 # Development validator (single node)
make -j run                   # Alias for fddev dev

# Testing
make -j unit-test             # Build all unit tests
make run-unit-test            # Run all unit tests
make -j integration-test      # Build integration tests
```

### **Binary Outputs**

After building, binaries are located in `build/native/gcc/bin/`:

| Binary | Description | Build Target |
|--------|-------------|--------------|
| `fdctl` | Frankendancer validator | `make fdctl` |
| `firedancer` | Pure Firedancer validator | `make firedancer` |
| `fddev` | Development validator | `make fddev` |
| `solana` | Solana CLI tool | `make solana` |
| `agave-ledger-tool` | Ledger inspection tool | `make agave-ledger-tool` |

---

## **Versioning Scheme**

From the README:

### **Frankendancer Versions** (v0.x.y)

Format: `v0.MINOR.PATCH`

- **Major version**: Always `0` (Frankendancer is hybrid)
- **Minor version**: Increments by 100 for each release (e.g., 100, 200, 300)
- **Patch version**: Encodes Agave version (e.g., `11714` = Agave v1.17.14)

Example: `v0.200.11901` = Frankendancer release 2, based on Agave v1.19.01

### **Firedancer Versions** (v1.x)

- Will start at `v1.0.0` when pure Firedancer is production-ready
- No Agave version encoding in patch number

---

## **Performance Characteristics**

### **Frankendancer**

**Advantages:**
- High-performance networking (kernel bypass via AF_XDP)
- Optimized signature verification (AVX-512 batching)
- Better DoS mitigation (connection limits, rate limiting)
- Improved block production performance while leader

**Bottlenecks:**
- Transaction execution still uses Agave runtime
- Consensus still uses Agave Tower BFT implementation
- Overall throughput limited by Agave components

### **Pure Firedancer (Expected)**

**Advantages:**
- All components optimized for performance
- No inter-language overhead (all C)
- More efficient memory layout (no Rust allocator)
- Tighter CPU cache utilization

**Trade-offs:**
- Requires full reimplementation of complex consensus logic
- More surface area for bugs (no battle-tested Agave code)

---

## **Security Boundaries**

### **Frankendancer**

**Trust Boundaries:**
1. **Firedancer tiles** → **Agave runtime**: Via shared memory (Tango + Funk)
   - Firedancer provides filtered, verified transactions
   - Agave trusts signature verification was done correctly
   - Potential for memory corruption bugs at interface

2. **Agave runtime** → **Firedancer tiles**: Via shared memory
   - Agave publishes execution results
   - Firedancer trusts state updates from Agave

**Process Isolation:**
- Each Firedancer tile runs in separate process with seccomp sandbox
- Agave validator runs as multi-threaded child process (less isolated)

### **Pure Firedancer**

**Trust Boundaries:**
- All tiles run with same trust model
- Consistent sandboxing across all components
- No cross-language memory sharing

---

## **Development Workflow**

### **Working on Firedancer Components**

If you're modifying networking, signature verification, or block production:
1. Edit files in `src/disco/`, `src/waltz/`, `src/ballet/`
2. Build with `make -j fdctl`
3. Test with `make -j unit-test && make run-unit-test`
4. Your changes affect Frankendancer only

### **Working on Agave Components**

If you need to modify execution, consensus, or state management:
1. Edit files in `agave/` submodule (Rust code)
2. Build with `make -j fdctl` (will rebuild Agave crate)
3. Both Frankendancer and standard Agave validator are affected

### **Working on Pure Firedancer**

If you're implementing C replacements for Agave components:
1. Edit files in `src/discof/`, `src/choreo/`, `src/flamenco/`
2. Build with `make -j firedancer`
3. Only pure Firedancer binary is affected (not production-ready)

---

## **Summary**

**Key Insight:** The boundary isn't about "which tiles" but rather **"which implementation of each tile"**. Frankendancer uses Firedancer's implementation for networking/block production and Agave's for execution/consensus.

### **Frankendancer (Now)**
- Build: `make fdctl solana`
- Implementation: Firedancer (C) for networking + Agave (Rust) for execution
- Communication: Shared memory (Tango + Funk)
- Status: Production-ready on testnet and mainnet-beta
- Binary: `fdctl` spawns both Firedancer tiles and Agave subprocess

### **Firedancer (Future)**
- Build: `make firedancer`
- Implementation: Pure C for everything
- Communication: All Tango IPC (no Rust FFI)
- Status: Under development, not production-ready
- Binary: `firedancer` runs all tiles in C

### **The Transition Path**

```
v0.100 (Frankendancer)
  ├─ Firedancer: NET, QUIC, VERIFY, DEDUP, PACK, SHRED, SIGN
  └─ Agave: RESOLV, BANK, POH, STORE, consensus

v0.200 (Frankendancer)
  ├─ Firedancer: + improved performance
  └─ Agave: updated to newer version

...

v1.0 (Pure Firedancer)
  └─ Firedancer: Everything (NET, QUIC, VERIFY, DEDUP, PACK,
                            RESOLV, BANK, POH, STORE, SHRED,
                            GOSSIP, REPLAY, TOWER, consensus)
```

---

## **References**

- Main README: [README.md](../README.md)
- Firedancer docs: [book/guide/firedancer.md](../book/guide/firedancer.md)
- Getting started: [book/guide/getting-started.md](../book/guide/getting-started.md)
- Architecture analysis: [SR/Architecture.md](Architecture.md)
- Transaction processing: [SR/Transaction_Processing.md](Transaction_Processing.md)
- Build system: [config/everything.mk](../config/everything.mk)

---

**END OF DOCUMENT**
