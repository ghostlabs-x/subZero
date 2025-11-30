#![no_std]
#![no_main]

use aya_bpf::{
    bindings::Layer,
    macros::xdp,
    maps::HashMap,
    programs::XdpContext,
    Error,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[xdp]
pub fn xdp_router(ctx: XdpContext) -> u32 {
    match try_xdp_router(ctx) {
        Ok(ret) => ret,
        Err(_) => 2, // XDP_DROP
    }
}

fn try_xdp_router(ctx: XdpContext) -> Result<u32, Error> {
    let ethhdr: *const EthHdr = ctx.layer(Layer::Ethernet)?.header();
    let ethhdr = unsafe { *ethhdr };

    if ethhdr.ether_type != EtherType::Ipv4 {
        return Ok(1); // XDP_PASS
    }

    let ipv4hdr: *const Ipv4Hdr = ctx.layer(Layer::Ipv4)?.header();
    let ipv4hdr = unsafe { *ipv4hdr };

    let src_ip = u32::from_be_bytes([
        ipv4hdr.src_addr.0[0],
        ipv4hdr.src_addr.0[1],
        ipv4hdr.src_addr.0[2],
        ipv4hdr.src_addr.0[3],
    ]);

    // === Spam protection ===
    let counter_key = src_ip;
    let mut counter = CLIENT_COUNTER.get(&counter_key).unwrap_or(&0u64);
    *counter += 1;
    if *counter > 100 {
        return Ok(0); // XDP_DROP
    }
    CLIENT_COUNTER.insert(&counter_key, counter, 0)?;

    // === Route table lookup ===
    if let Some(&dest_ip) = ROUTE_TABLE.get(&src_ip) {
        // Rewrite destination IP
        let mut ipv4hdr_mut = unsafe { &mut *(ipv4hdr as *mut Ipv4Hdr) };
        let old_dest = ipv4hdr_mut.dst_addr;
        ipv4hdr_mut.dst_addr = u32::from_be_bytes(dest_ip.to_be_bytes());

        // Recalculate checksum
        ipv4hdr_mut.checksum = ipv4hdr_mut.calc_checksum()?;

        Ok(1) // XDP_TX
    } else {
        Ok(1) // XDP_PASS (default)
    }
}

// eBPF Maps (no logging macros)
#[aya_bpf::map]
static CLIENT_COUNTER: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(100_000, 0);

#[aya_bpf::map]
static ROUTE_TABLE: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(65_536, 0);