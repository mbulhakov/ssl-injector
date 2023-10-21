use anyhow::anyhow;
use aya::programs::UProbe;
use aya::{include_bytes_aligned, maps::perf::AsyncPerfEventArray, util::online_cpus, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use log::{debug, error, info, warn};
use log4rs::config::Deserializers;
use ssl_injector_common::SslEntry;
use std::borrow::Cow;
use std::fmt::Write;
use std::mem;
use tokio::signal;

fn start_monitoring(
    bpf: &mut Bpf,
    map_name: Cow<'static, str>,
    method_name: Cow<'static, str>,
) -> Result<(), anyhow::Error> {
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(
        bpf.take_map(&map_name)
            .ok_or(anyhow!("Failed to take map"))?,
    )?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        let method_name = method_name.clone();
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
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const SslEntry;
                    let ssl_entry = unsafe { ptr.read_unaligned() };

                    if ssl_entry.size > 0 {
                        let buffer = &ssl_entry.buffer[..ssl_entry.size];
                        let buffer_display: Cow<str> = match std::str::from_utf8(buffer) {
                            // converting to hex representation in case of failure
                            Err(_) => Cow::from(format!(
                                "[HEX] {}",
                                buffer.iter().fold(String::new(), |mut output, b| {
                                    let _ = write!(output, "{b:02X}");
                                    output
                                }),
                            )),

                            Ok(s) => Cow::from(s),
                        };

                        info!(
                            "{}: \n========\n{}\n========\n",
                            method_name, buffer_display
                        );
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
    let ssl_write_program: &mut UProbe = bpf.program_mut("ssl_write").unwrap().try_into()?;
    ssl_write_program.load()?;
    ssl_write_program.attach(Some("SSL_write"), 0, "libssl", None)?;

    let ssl_write_ret_program: &mut UProbe =
        bpf.program_mut("ssl_write_ret").unwrap().try_into()?;
    ssl_write_ret_program.load()?;
    ssl_write_ret_program.attach(Some("SSL_write"), 0, "libssl", None)?;

    start_monitoring(
        &mut bpf,
        Cow::from("SSL_WRITE_EVENTS"),
        Cow::from("SSL_write"),
    )?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
