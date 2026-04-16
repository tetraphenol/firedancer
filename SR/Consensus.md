# Consensus Layer - Security Analysis

**Components:** Equivocation Detection, Ghost Fork Choice, Tower BFT, Gossip
**Source:** `/home/user/firedancer/src/choreo/`, `/home/user/firedancer/src/flamenco/gossip/`
**Analysis Date:** November 6, 2025

---

## Executive Summary

Firedancer's consensus layer implements Solana's Tower BFT consensus with equivocation detection and Ghost fork choice. Analysis identified **1 critical vulnerability** (equivocation pool exhaustion) and **3 high-severity issues** affecting consensus security.

### Critical Findings

| ID | Severity | Component | Issue | Location |
|----|----------|-----------|-------|----------|
| 1 | **CRITICAL** | Equivocation | No eviction policy | `choreo/eqvoc/fd_eqvoc.c:113` |
| 2 | **HIGH** | Ghost | Pool exhaustion | `choreo/ghost/fd_ghost.c:299` |
| 3 | **HIGH** | Gossip | No double-vote detection | `flamenco/gossip/fd_gossip.c` |
| 4 | **MEDIUM** | Reassembly | CMR overwriting | `discof/reasm/fd_reasm.c:186` |

---

## Equivocation Detection

### Architecture

**Location:** `/home/user/firedancer/src/choreo/eqvoc/`

**Purpose:** Detect Byzantine validators producing conflicting blocks in same slot

**Components:**
- FEC proof pool - Stores forward error correction proofs
- Chunk tracking - Assembles equivocation proofs from chunks
- Proof verification - Validates equivocation claims

### CRITICAL: Pool Exhaustion Without Eviction

**File:** `fd_eqvoc.c`, Lines 113-115

```c
/* FIXME eviction */
if( FD_UNLIKELY( !fd_eqvoc_fec_pool_free( eqvoc->fec_pool ) ) ) 
  FD_LOG_ERR(( "[%s] map full.", __func__ ));
```

**Vulnerability:**
- FEC proof pool can fill completely
- No LRU or TTL-based eviction
- New equivocation proofs rejected when pool full

**Attack Scenario:**
```
1. Attacker floods network with many FEC sets
2. Equivocation pool fills with partial proofs
3. Legitimate equivocation proof arrives
4. Pool full → proof rejected
5. Byzantine validator escapes detection
```

**Impact:**
- Equivocating validators not detected
- Consensus safety compromised
- Network can fork under Byzantine conditions

**Proof of Concept:**
```c
// Fill pool with junk FEC sets
for( int i=0; i<POOL_SIZE; i++ ) {
  fd_eqvoc_proof_chunk_insert( eqvoc, fake_chunk );
}

// Now legitimate equivocation cannot be stored
fd_eqvoc_proof_chunk_insert( eqvoc, real_equivocation );
// → Returns error, equivocation not tracked
```

**Recommendation:**
```c
/* Implement LRU eviction */
if( !fd_eqvoc_fec_pool_free( eqvoc->fec_pool ) ) {
  /* Evict oldest entry */
  fd_eqvoc_fec_t * oldest = find_oldest_fec( eqvoc );
  if( oldest->last_seen + TTL < now ) {
    fd_eqvoc_fec_pool_remove( eqvoc->fec_pool, oldest );
  } else {
    return FD_EQVOC_ERR_POOL_FULL;
  }
}
```

---

### Proof Assembly

**File:** `fd_eqvoc.c`, Lines 189-217

**Function:** `fd_eqvoc_proof_chunk_insert()`

**Issue:** Wallclock-Based Overwriting

```c
/* Lines 191-197: Replace chunk if newer */
if( chunk->wallclock > existing->wallclock ) {
  *existing = *chunk;  /* Overwrite without full validation */
}
```

**Concern:**
- Chunks can be replaced based solely on wallclock comparison
- No cryptographic validation of chunk authenticity
- Multiple attackers can race to inject contradicting chunks

**Impact:** LOW-MEDIUM
- Equivocation detection may use wrong chunks
- Proof assembly could fail
- Mitigated by downstream proof verification

---

## Ghost Fork Choice

### Architecture

**Location:** `/home/user/firedancer/src/choreo/ghost/`

**Purpose:** Implement Greedy Heaviest-Observed Sub-Tree fork choice

**Algorithm:**
1. Track all blocks and their parent relationships
2. Weight each block by stake that voted for it
3. Choose fork with heaviest subtree

### HIGH: Pool Exhaustion

**File:** `fd_ghost.c`, Lines 299-300

```c
if( FD_UNLIKELY( !fd_ghost_pool_free( pool ) ) ) { 
  FD_LOG_WARNING(( "[%s] ghost full." )); 
  return NULL; 
}
```

**Issue:**
- Ghost pool stores all observed blocks
- No automatic pruning of old forks
- Pool can fill over time

**Attack Scenario:**
```
Long-running validator:
1. Network experiences many forks
2. Ghost pool fills with fork data
3. New block arrives
4. Pool full → cannot add to ghost tree
5. Fork choice fails
```

**Impact:**
- Fork choice algorithm fails
- Validator cannot determine canonical chain
- Consensus participation disrupted

**Recommendation:**
```c
/* Auto-prune old forks */
if( !fd_ghost_pool_free( pool ) ) {
  /* Prune forks older than finalized slot */
  fd_ghost_prune_old_forks( ghost, finalized_slot );
  
  /* Prune low-stake minority forks */
  fd_ghost_prune_minority_forks( ghost, stake_threshold );
}
```

---

### Duplicate Block Tracking

**File:** `fd_ghost.c`, Lines 127-132

```c
/* Track equivocating blocks via linked list */
ele_slot->eqvoc = fd_ghost_pool_idx( pool, ele );
```

**Concern:**
- Equivocating blocks tracked but validation depends on reasm layer
- If reasm fails to detect equivocation, ghost sees duplicate as valid

**Impact:** MEDIUM
- Duplicate blocks can poison fork choice
- Weight calculations incorrect
- Mitigated by equivocation detection in reasm

---

## Tower BFT Voting

### Architecture

**Location:** `/home/user/firedancer/src/choreo/tower/`

**Purpose:** Vote lockouts prevent validators from voting on conflicting forks

**Lockout Mechanism:**
- Each vote locks out validator for 2^n slots
- Doubling lockout with each consecutive vote
- Cannot switch forks until lockout expires

### Timestamp Validation

**File:** `fd_tower.h`

**Issue:** Limited Timestamp Bounds Checking

**Concern:**
- Tower uses slot-based lockouts
- Wallclock timestamp manipulation could affect vote expiration in edge cases

**Impact:** LOW
- Slot numbers are cryptographically bound
- Timestamp manipulation limited impact
- Mitigated by PoH timing

---

## Gossip Protocol

### Architecture

**Location:** `/home/user/firedancer/src/flamenco/gossip/`

**Purpose:** 
- Peer discovery
- Vote dissemination
- Block metadata propagation

### HIGH: No Double-Vote Detection

**File:** `fd_gossip.c`, Lines ~445-455

**Issue:** Gossip forwards votes without explicit equivocation checks

```c
/* Vote forwarding (pseudocode) */
if( received_vote ) {
  /* No check for conflicting prior vote */
  forward_to_peers( vote );
}
```

**Attack Scenario:**
```
1. Byzantine validator creates two conflicting votes:
   - Vote A: slot 1000, hash H1
   - Vote B: slot 1000, hash H2
2. Sends Vote A to peers in region 1
3. Sends Vote B to peers in region 2
4. Both votes propagate before tower detects equivocation
5. Network sees conflicting votes, slowing consensus
```

**Impact:**
- Conflicting votes poison peer state
- Consensus convergence slowed
- Tower eventually detects, but damage done

**Recommendation:**
```c
/* Cache recent votes per validator */
fd_vote_t * prev_vote = vote_cache_get( validator_pubkey );

if( prev_vote && prev_vote->slot == new_vote->slot ) {
  if( !fd_hash_eq( &prev_vote->hash, &new_vote->hash ) ) {
    /* Double vote detected */
    FD_LOG_WARNING(( "Equivocation: validator %s", pubkey ));
    /* Report to equivocation detector */
    fd_eqvoc_report( eqvoc, validator_pubkey, prev_vote, new_vote );
    return; /* Don't forward */
  }
}

/* Cache and forward */
vote_cache_insert( validator_pubkey, new_vote );
forward_to_peers( new_vote );
```

---

### Sybil Attack Resistance

**File:** `fd_gossip.c`, Lines 137-155

**Function:** `ping_tracker_change()`

**Mechanism:**
- Peer status based on ping responses
- Transitions: INACTIVE → ACTIVE based on pings

**Concern:**
- Peer status solely based on network reachability
- No stake-weighted reputation
- Attackers can quickly cycle ACTIVE/INACTIVE states

**Mitigation:**
- Stake-weighted peer selection (implemented elsewhere)
- Bloom filters limit message propagation

**Impact:** LOW-MEDIUM
- Mitigated by stake weighting
- Bloom filter false positive rate: 10%

---

### Bloom Filter False Positives

**File:** `fd_gossip.c`, Line 19

```c
#define BLOOM_FALSE_POSITIVE_RATE (0.1)  /* 10% */
```

**Issue:**
- 10% of legitimate values filtered incorrectly
- Critical consensus messages (votes, blocks) could be dropped

**Impact:** MEDIUM
- Slows consensus convergence
- Legitimate votes/blocks may not propagate
- Eventually corrected by repair mechanism

**Recommendation:**
- Reduce false positive rate for critical message types
- Implement priority-based bloom filter (consensus messages exempt)

---

## Shred Validation

### Merkle Chain Integrity

**Location:** `/home/user/firedancer/src/discof/reasm/`

### MEDIUM: CMR Overwriting

**File:** `fd_reasm.c`, Lines 186-198

**Function:** `overwrite_invalid_cmr()`

```c
static void
overwrite_invalid_cmr( fd_reasm_t * reasm, fd_reasm_fec_t * child ) {
  if( FD_UNLIKELY( child->fec_set_idx==0 && !fd_reasm_query( reasm, &child->cmr ) ) ) {
    slot_mr_t * slot_mr_parent = slot_mr_query( reasm->slot_mr, child->slot - child->parent_off, NULL );
    if( FD_LIKELY( slot_mr_parent ) ) {
      child->cmr = parent->key; /* Overwrite without full validation */
    }
  }
}
```

**Issue:**
- CMR (Chained Merkle Root) overwritten based on slot lookup
- No cryptographic verification that parent hash is correct
- Merkle chain integrity not validated

**Attack Scenario:**
```
1. Attacker crafts shreds with invalid CMR
2. Reasm looks up parent slot
3. Overwrites CMR with parent hash (no validation)
4. Block appears chained but merkle proof invalid
5. Fork attack: blocks appear connected but are discontinuous
```

**Impact:**
- Broken merkle chain integrity
- Blocks appear chained but are actually discontinuous
- Potential for fork attacks

**Recommendation:**
```c
/* Validate merkle root before chaining */
if( !validate_merkle_proof( child, parent ) ) {
  FD_LOG_ERR(( "Invalid merkle chain" ));
  return ERROR;
}
child->cmr = parent->key;
```

---

### Equivocation Detection Limitations

**File:** `fd_reasm.h`, Lines 26-39

**Documentation:**
```c
/* Note: not all cases of equivocation can be detected by the reasm */
```

**Issue:**
- Equivocating FEC sets in same slot may evade detection
- Only detects when merkle roots conflict
- Subtle equivocations could pass through

**Impact:** LOW-MEDIUM
- Relies on downstream equivocation detection (choreo/eqvoc)
- Defense in depth approach

---

## Vote Lifecycle Security

### Vote Creation

**Components:**
1. Validator creates vote transaction
2. Signs with vote account key
3. Broadcasts via gossip (UDP, no QUIC)

### Vote Validation

**Checks:**
- ✅ Signature verification (ED25519)
- ✅ Vote account authority
- ✅ Slot number validity
- ❌ Double-vote check (missing in gossip)

### Vote Propagation

**Protocol:**
- Gossip (UDP port 8001)
- Push/pull mechanism
- Bloom filters for deduplication

**Security Gaps:**
- No double-vote check at gossip layer (HIGH finding)
- 10% bloom filter false positive rate (MEDIUM concern)

---

## Recommendations

### Critical (Immediate)

1. **Implement Equivocation Pool Eviction**
   - LRU with TTL (e.g., 30 seconds)
   - Prioritize high-stake validators
   - Monitor pool capacity

2. **Add Ghost Pool Pruning**
   - Auto-prune forks older than finalized
   - Remove low-stake minority forks
   - Implement pruning threshold

### High Priority

3. **Add Gossip Double-Vote Detection**
   - Cache recent votes per validator
   - Detect conflicting votes at gossip layer
   - Report to equivocation detector

4. **Validate CMR Cryptographically**
   - Verify merkle proof before chaining
   - Add explicit integrity checks
   - Detect broken merkle chains

### Medium Priority

5. **Reduce Bloom Filter False Positives**
   - Lower rate for consensus messages
   - Implement priority classes
   - Monitor message loss

6. **Add Stake-Weighted Reputation**
   - Weight peers by stake
   - Prioritize high-stake validators
   - Limit low-stake peer impact

---

## Testing Recommendations

### Adversarial Testing

1. **Equivocation Injection**
   - Generate conflicting blocks
   - Test detection at each layer
   - Verify pool capacity handling

2. **Fork Bombing**
   - Create many competing forks
   - Test ghost pruning
   - Measure memory usage

3. **Double-Vote Attack**
   - Broadcast conflicting votes
   - Verify gossip detection
   - Test tower lockout

### Load Testing

1. **Pool Capacity**
   - Fill equivocation pool
   - Measure eviction behavior
   - Test under load

2. **Ghost Scalability**
   - Many concurrent forks
   - Long-running validator
   - Pruning effectiveness

---

## References

- Solana Consensus Documentation
- Tower BFT Paper
- Source: `/home/user/firedancer/src/choreo/`
- Source: `/home/user/firedancer/src/flamenco/gossip/`
- Related: `SR/Architecture.md`, `SR/Network_Layer.md`

**END OF CONSENSUS ANALYSIS**
