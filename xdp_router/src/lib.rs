// xdp_router/src/lib.rs
#![no_std]
#![no_main]

use core::mem;
use redbpf::xdp_action::XdpAction;
use redbpf::{c, hash_map, xdp};

#[xdp]
pub extern "C" fn xdp_router(ctx: xdp::XdpContext) -> XdpAction {
    // Parse Ethernet → IPv4/IPv6
    let eth = match ctx.eth() {
        Ok(eth) => eth,
        Err(_) => return XdpAction::Drop,
    };

    // Only handle IPv4 for simplicity in POC (add IPv6 later)
    if eth.ethertype() != c::ETH_P_IP {
        return XdpAction::Pass; // Let kernel handle non-IP
    }

    let iph = match ctx.ipv4() {
        Ok(iph) => iph,
        Err(_) => return XdpAction::Pass,
    };

    let src_ip = iph.source();

    // === Spam protection (per-client rate limiting) ===
    let mut counter = unsafe { CLIENT_COUNTER.get_or_insert(src_ip, || 0) };
    *counter += 1;
    if *counter > 100 {
        // >100 pps from one mobile client → drop as spam
        return XdpAction::Drop;
    }

    // === Dynamic routing table lookup ===
    // Map: client_ip_prefix (u32) → destination_ip (u32)
    if let Some(&dest_ip) = ROUTE_TABLE.get(&src_ip) {
        // Rewrite destination IP and recalc checksum
        let old_dest = iph.destination();
        iph.set_destination(dest_ip);
        iph.csum_replace4(&old_dest, &dest_ip);
        
        return XdpAction::Tx; // Send back out wg0 to the chosen DoubleZero node
    }

    // No route → fall back to default (e.g. main Helius endpoint)
    XdpAction::Pass
}

// eBPF maps
hash_map!(ROUTE_TABLE, u32, u32, 65536);     // client_prefix → doublezero_ip
hash_map!(CLIENT_COUNTER, u32, u64, 100_000); // per-client packet counter (reset by userspace)