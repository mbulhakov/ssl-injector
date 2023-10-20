use anyhow::anyhow;
use aya::programs::UProbe;
use aya::{include_bytes_aligned, maps::perf::AsyncPerfEventArray, util::online_cpus, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{debug, error, info, warn};
use log4rs::config::Deserializers;
use rand::Rng;
use ssl_injector_common::SslEntry;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::signal;

fn start_monitoring(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    // Process events from the perf buffer
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(
        bpf.take_map("SSL_WRITE_EVENTS")
            .ok_or(anyhow!("Failed to take map"))?,
    )?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        info!("CPU {}", cpu);
        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(mem::size_of::<SslEntry>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await;
                if let Err(e) = events {
                    error!("{}", e);
                    continue;
                }
                let events = events.unwrap();
                for i in 0..events.read {
                    // read the event
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const SslEntry;
                    let ssl_entry = unsafe { ptr.read_unaligned() };

                    // Get the current timestamp
                    let timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    // Generate a random string for the file name
                    let random_string: String = rand::thread_rng()
                        .sample_iter(&rand::distributions::Alphanumeric)
                        .take(8)
                        .map(char::from)
                        .collect();

                    // Create the random file name
                    let random_filename = format!("/tmp/{}_{}.txt", timestamp, random_string);

                    // Create and write data to the random file
                    if let Ok(f) = File::create(&random_filename) {
                        let mut writer = BufWriter::new(f);
                        if let Ok(()) = writer.write_all(&ssl_entry.buffer[..ssl_entry.size]) {
                            println!("Written data to: {}", random_filename);
                        }
                    } else {
                        println!("Failed to create or write to the file.");
                    }
                }
            }
        });
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config = log4rs::config::load_config_file("/etc/log4rs.yml", Deserializers::default())
        .expect("Failed to load logger config");
    log4rs::init_config(config).expect("Failed to init logger");

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ssl-injector"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ssl-injector"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut UProbe = bpf.program_mut("ssl_write").unwrap().try_into()?;
    program.load()?;

    program.attach(Some("SSL_write"), 0, "libssl", None)?;

    start_monitoring(&mut bpf)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
