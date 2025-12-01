use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use clap::Parser;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "wg0")]
    interface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    // Load BPF
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/libxdp_router.so"
    ))?;

    // Attach XDP to wg0
    let program: &mut Xdp = bpf.program_mut("xdp_router").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.interface, XdpFlags::default())?;

    println!("XDP router attached to {} – Ctrl+C to stop", args.interface);
    
    // Share bpf with spawned task using Arc
    let bpf = Arc::new(bpf);
    let bpf_clone = bpf.clone();
    
    // Spawn task to update route table
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            
            // Mock latency oracle (replace with DoubleZero feed)
            let us_west_client = Ipv4Addr::new(10, 0, 0, 0);
            let low_latency_dz = Ipv4Addr::new(203, 0, 113, 50);
            
            // Access map through the Arc-wrapped bpf
            if let Some(map) = bpf_clone.map_mut("ROUTE_TABLE") {
                if let Ok(mut route_map) = HashMap::<_, u32, u32>::try_from(map) {
                    route_map.insert(
                        &u32::from(us_west_client),
                        &u32::from(low_latency_dz),
                        0,
                    ).expect("Failed to update route");
                }
            }
        }
    });

    // Keep bpf alive for the duration of the program
    tokio::signal::ctrl_c().await?;
    Ok(())
}