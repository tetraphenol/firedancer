# NET-001: IP Fragmentation Bypass in XDP BPF Filter and Userspace Parser

## Severity
MEDIUM (Network-layer validation bypass)

## Summary
Neither the kernel-side eBPF program (`fd_xdp1.c`) nor the userspace `net_rx_packet` function check the IP `net_frag_off` field for the More Fragments (MF) bit or a non-zero fragment offset. A non-first IP fragment bypasses the port-based routing filter and delivers attacker-controlled raw bytes to downstream tiles (QUIC, gossip, repair) as if they were valid UDP payloads.

## Vulnerability Details

**Location:**
- BPF: `src/waltz/xdp/fd_xdp1.c:95-122`
- Userspace: `src/disco/net/xdp/fd_xdp_tile.c:892-963`
- QUIC: `src/waltz/quic/fd_quic.c:2390-2414`

**Root Cause:**
The BPF program checks `ip4_hdr->protocol == UDP` and `ip4_hdr->verihl` (IHL), but never reads the 2-byte `net_frag_off` field at IP offset +6. A non-first IP fragment (fragment offset > 0) passes the BPF filter and is redirected to the AF_XDP ring.

In userspace, `net_rx_packet` computes `udp = (uchar*)iphdr + iplen` (line 950), which for a non-first fragment does not point to a UDP header - it points into the fragment payload. The bytes at this position are read as `udp_hdr->net_dport` for port-based routing and as `udp_hdr->net_len` for size calculation.

AF_XDP bypasses the kernel network stack entirely, so OS-level IP reassembly never occurs.

**Attack Vector:**
1. Attacker sends a crafted two-fragment UDP packet targeting the QUIC TPU port
2. First fragment: valid IP+UDP header with correct destination port, small payload
3. Second fragment: fragment offset > 0, no UDP header, payload crafted so that bytes at the UDP header position match the target port number
4. The second fragment passes the BPF filter (protocol=UDP, no frag check)
5. Userspace reads attacker-controlled bytes as UDP port and routes to the QUIC tile
6. QUIC tile receives raw fragment data as a "QUIC datagram"

**Practical impact:**
The QUIC parser (`fd_quic_process_packet_impl`) re-parses IP+UDP headers from the delivered packet. For a non-first fragment, the IP header is valid but the "UDP" bytes are attacker-controlled. The parser's validation at line 2409 (`net_tot_len <= cur_sz`) and line 2440 (`pkt.udp->net_len <= cur_sz + rc`) may pass or fail depending on the crafted values. On pass, the attacker delivers arbitrary bytes to the QUIC long/short header parser.

While QUIC's own cryptographic protections (connection ID matching, packet decryption) would reject most crafted data, the fragment bypass itself constitutes a network-layer validation bypass that could be chained with other issues.

## Notes
- The `fd_ip4.h` header already provides `fd_ip4_hdr_net_frag_off_is_unfragmented()` - the check logic exists but is not used in either the BPF program or `net_rx_packet`
- The fix is to check `(frag_off & 0xff3f) != 0` in both the BPF program and userspace parser, rejecting all fragments
- This is not covered by known issue #9165 (which addresses QUIC-layer issues, not IP-layer parsing)
