use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{InterfaceLink, Xdp, XdpFlags},
    Bpf,
};
use clap::Parser;
use std::net::Ipv4Addr;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "wg0")]
    interface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    // Load BPF
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../xdp_router/target/bpfel-unknown-none/release/xdp_router"
    ))?;

    // Attach XDP to wg0
    let program: &mut Xdp = bpf.program_mut("xdp_router").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.interface, XdpFlags::default())?;

    // Route table updater (every 10s)
    let route_map = HashMap::try_from(bpf.map_mut("ROUTE_TABLE").unwrap())?;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            
            // Mock latency oracle (replace with DoubleZero feed)
            let us_west_client = Ipv4Addr::new(10, 0, 0, 0);
            let low_latency_dz = Ipv4Addr::new(203, 0, 113, 50);
            
            route_map.insert(
                &u32::from(us_west_client),
                &u32::from(low_latency_dz),
                0,
            ).expect("Failed to update route");
        }
    });

    println!("XDP router attached to {} – Ctrl+C to stop", args.interface);
    tokio::signal::ctrl_c().await?;
    Ok(())
}