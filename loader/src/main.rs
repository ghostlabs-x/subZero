// loader/src/main.rs
use libbpf_rs::{MapHandle, Program};
use std::net::Ipv4Addr;

fn main() -> anyhow::Result<()> {
    let mut skel = xdp_router::XdpRouterSkel::load()?;
    skel.progs_mut().xdp_router().attach("wg0")?;

    let route_map = skel.maps_mut().route_table();
    let counter_map = skel.maps_mut().client_counter();

    // Example: Route all US-West clients to a low-latency DoubleZero node
    route_map.update(
        &(Ipv4Addr::new(10, 0, 0, 0).into()),
        &(Ipv4Addr::new(203, 0, 113, 50).into()),
        libbpf_rs::MapFlags::ANY,
    )?;

    // Reset counters every 1s (anti-spam)
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        counter_map.clear();
    });

    println!("XDP router loaded on wg0 – press Ctrl+C to stop");
    loop { std::thread::sleep(std::time::Duration::from_secs(3600)); }
}