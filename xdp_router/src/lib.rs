#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// Helper function to safely access packet data at a given offset
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

// Helper function to safely access mutable packet data at a given offset
#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

#[xdp]
pub fn xdp_router(ctx: XdpContext) -> u32 {
    match try_xdp_router(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

fn try_xdp_router(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let src_ip = u32::from_be_bytes(src_addr);

    // === Spam protection ===
    let counter_key = src_ip;
    let mut counter = CLIENT_COUNTER.get(&counter_key).copied().unwrap_or(0u64);
    counter += 1;
    if counter > 100 {
        return Ok(xdp_action::XDP_DROP);
    }
    CLIENT_COUNTER.insert(&counter_key, &counter, 0).map_err(|_| ())?;

    // === Route table lookup ===
    if let Some(&dest_ip) = ROUTE_TABLE.get(&src_ip) {
        // Rewrite destination IP
        let ipv4hdr_mut: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
        unsafe {
            (*ipv4hdr_mut).dst_addr = dest_ip.to_be_bytes();
            
            // Set checksum to 0 (kernel will recalculate if needed)
            // The checksum field is at offset 10 in the IPv4 header (2 bytes)
            let header_ptr = (ipv4hdr_mut as *mut u8).add(10);
            *(header_ptr as *mut u16) = 0u16.to_be();
        }

        Ok(xdp_action::XDP_TX)
    } else {
        Ok(xdp_action::XDP_PASS)
    }
}

// eBPF Maps
#[map]
static mut CLIENT_COUNTER: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(100_000, 0);

#[map]
static mut ROUTE_TABLE: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(65_536, 0);