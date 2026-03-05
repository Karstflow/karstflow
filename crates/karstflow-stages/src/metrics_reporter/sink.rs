use crate::errors::StageError;
use crate::MetricsOutputTarget;
use std::net::UdpSocket;
use std::{fs::OpenOptions, io::Write};

pub(crate) fn emit_line(output_target: &MetricsOutputTarget, line: &str) -> Result<(), StageError> {
    match output_target {
        MetricsOutputTarget::Stdout => {
            println!("{line}");
            Ok(())
        }
        MetricsOutputTarget::File(path) => {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|source| StageError::FileOpen {
                    path: path.clone(),
                    source,
                })?;
            writeln!(file, "{line}").map_err(|source| StageError::FileWrite {
                path: path.clone(),
                source,
            })?;
            Ok(())
        }
        MetricsOutputTarget::Udp(target_address) => {
            let socket = UdpSocket::bind("0.0.0.0:0").map_err(StageError::UdpBind)?;
            socket
                .send_to(line.as_bytes(), target_address)
                .map_err(|source| StageError::UdpSend {
                    target: *target_address,
                    source,
                })?;
            Ok(())
        }
        MetricsOutputTarget::Http => {
            // Http target is handled directly by MetricsReporter::tick()
            // writing to the shared MetricsContent buffer.
            Ok(())
        }
    }
}
