//! Turbine shred receiver — receives shred packets from peer validators
//! and feeds them directly into ShredCollector via the direct shred channel.
//!
//! Bypasses FEC resolution for now — received shreds go straight to the
//! ShredCollector which assembles complete slots from data shreds.
//!
//! TODO: Route through ShredNetworkService FEC pipeline once FEC resolution
//! is debugged for cross-node shreds.

use karstflow_mesh::DualSender;
use karstflow_types::shred::{Shred, ShredParser};
use std::net::{SocketAddr, UdpSocket};
use tracing::{info, warn};

/// Spawn a background thread that listens for turbine shred packets
/// and feeds parsed shreds directly into ShredCollector.
pub(crate) fn spawn_turbine_receiver(
    bind_addr: SocketAddr,
    mut shred_sender: DualSender<Shred>,
) -> Option<std::thread::JoinHandle<()>> {
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => {
            let _ = s.set_read_timeout(Some(std::time::Duration::from_millis(50)));
            info!(%bind_addr, "turbine-receiver: listening for shred packets");
            s
        }
        Err(e) => {
            warn!(%bind_addr, error = %e, "turbine-receiver: failed to bind");
            return None;
        }
    };

    std::thread::Builder::new()
        .name("turbine-receiver".into())
        .spawn(move || {
            let mut buf = [0u8; 1280];
            let mut received = 0u64;

            loop {
                match socket.recv_from(&mut buf) {
                    Ok((len, _src)) if len >= 64 => {
                        if let Ok(shred) = ShredParser::parse(&buf[..len]) {
                            received += 1;
                            if received <= 5 || received.is_multiple_of(100) {
                                info!(
                                    received,
                                    slot = shred.slot(),
                                    index = shred.index(),
                                    is_data = !shred.is_coding(),
                                    is_last = shred.is_last_in_slot(),
                                    "turbine-receiver: shred → ShredCollector"
                                );
                            }
                            let _ = shred_sender.try_send(shred);
                        }
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(_) => continue,
                }
            }
        })
        .ok()
}
