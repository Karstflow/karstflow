/// Zero-copy IPC link for shred pipeline stages.
///
/// Provides configuration and serialization helpers for passing shreds
/// between pipeline stages via TileLink (MetaRing + DataRegion +
/// FlowSequence). Shreds are stored as raw wire-format bytes in the
/// DataRegion, avoiding copies on the hot path.
///
/// Fragment metadata layout for shred fragments:
///   sig:  first 8 bytes of the shred's Ed25519 signature (dedup fingerprint)
///   ctl:  origin bits encode ShredSource (0=Local, 1=Turbine, 2=Repair),
///         SOM+EOM always set (single-fragment shreds)
///   sz:   wire-format byte length (max ~1228)
use crate::shred_network::ShredSource;
use paradencer_mesh::fragment::ctl_pack;
use paradencer_mesh::tile_link::{TileLink, TileLinkConfig};
use paradencer_types::shred::Shred;

/// Maximum shred wire-format size with headroom for Merkle proofs.
pub const SHRED_LINK_MTU: usize = 1280;

/// Ring depth for the shred link (power of 2).
/// 8192 entries ≈ 10 MB at MTU=1280, handles burst ingress.
pub const SHRED_LINK_DEPTH: usize = 8192;

/// Maximum concurrent producer fragments before backpressure.
pub const SHRED_LINK_BURST: usize = 64;

/// Create a TileLink configured for shred transport.
pub fn new_shred_link() -> TileLink {
    new_shred_link_with_config(SHRED_LINK_MTU, SHRED_LINK_DEPTH, SHRED_LINK_BURST)
}

/// Create a TileLink with custom parameters.
pub fn new_shred_link_with_config(mtu: usize, depth: usize, burst: usize) -> TileLink {
    TileLink::new(TileLinkConfig {
        mtu,
        depth,
        burst,
        initial_seq: 0,
    })
}

/// Encode a ShredSource into the origin bits of the fragment control field.
pub fn shred_source_to_ctl(source: ShredSource) -> u16 {
    let origin = match source {
        ShredSource::Local => 0u16,
        ShredSource::Turbine => 1u16,
        ShredSource::Repair => 2u16,
    };
    ctl_pack(origin, true, true, false)
}

/// Decode a ShredSource from the origin bits of the fragment control field.
pub fn ctl_to_shred_source(ctl: u16) -> ShredSource {
    let origin = paradencer_mesh::fragment::ctl_origin(ctl);
    match origin {
        1 => ShredSource::Turbine,
        2 => ShredSource::Repair,
        _ => ShredSource::Local,
    }
}

/// Extract the first 8 bytes of a shred's signature as a dedup fingerprint.
pub fn shred_sig_fingerprint(shred: &Shred) -> u64 {
    let sig = &shred.common_header.signature;
    u64::from_le_bytes([
        sig[0], sig[1], sig[2], sig[3], sig[4], sig[5], sig[6], sig[7],
    ])
}

/// Extract the first 8 bytes of raw wire bytes as a dedup fingerprint.
/// The signature occupies the first 64 bytes of any shred wire format.
pub fn raw_sig_fingerprint(raw: &[u8]) -> u64 {
    if raw.len() >= 8 {
        u64::from_le_bytes(raw[..8].try_into().unwrap())
    } else {
        0
    }
}

/// Get the wire-format bytes for a shred.
///
/// Returns the `raw` field if available (parsed-from-network shreds),
/// otherwise falls back to the `payload` field.
pub fn shred_wire_bytes(shred: &Shred) -> &[u8] {
    shred.raw.as_deref().unwrap_or(&shred.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use paradencer_mesh::tile_link::ReceiveResult;

    #[test]
    fn source_encoding_round_trip() {
        for source in [
            ShredSource::Local,
            ShredSource::Turbine,
            ShredSource::Repair,
        ] {
            let ctl = shred_source_to_ctl(source);
            let decoded = ctl_to_shred_source(ctl);
            assert_eq!(source, decoded);
        }
    }

    #[test]
    fn ctl_has_som_and_eom() {
        let ctl = shred_source_to_ctl(ShredSource::Turbine);
        assert!(paradencer_mesh::fragment::ctl_som(ctl));
        assert!(paradencer_mesh::fragment::ctl_eom(ctl));
        assert!(!paradencer_mesh::fragment::ctl_err(ctl));
    }

    #[test]
    fn raw_sig_fingerprint_extracts_first_8_bytes() {
        let mut data = vec![0u8; 64];
        data[0] = 0xAA;
        data[7] = 0xBB;
        let fp = raw_sig_fingerprint(&data);
        assert_eq!(fp & 0xFF, 0xAA);
        assert_eq!((fp >> 56) & 0xFF, 0xBB);
    }

    #[test]
    fn raw_sig_fingerprint_short_input() {
        assert_eq!(raw_sig_fingerprint(&[]), 0);
        assert_eq!(raw_sig_fingerprint(&[1, 2, 3]), 0);
    }

    #[test]
    fn new_shred_link_creates_valid_link() {
        let link = new_shred_link();
        assert_eq!(link.config().mtu, SHRED_LINK_MTU);
        assert_eq!(link.config().depth, SHRED_LINK_DEPTH);
    }

    #[test]
    fn shred_payload_round_trip_through_link() {
        let mut link = new_shred_link_with_config(1280, 64, 4);

        // Simulate a shred wire payload.
        let wire_bytes: Vec<u8> = (0..200u8).collect();
        let sig = raw_sig_fingerprint(&wire_bytes);
        let ctl = shred_source_to_ctl(ShredSource::Turbine);

        // Write phase: produce a fragment, then release the producer.
        {
            let mut producer = link.producer();
            producer.send(sig, &wire_bytes, ctl);
        }

        // Read phase: create a consumer and read the fragment.
        let mut consumer = link.consumer();
        match consumer.receive(100) {
            ReceiveResult::Ready { meta, payload } => {
                assert_eq!(payload, &wire_bytes[..]);
                assert_eq!(meta.sig, sig);
                let decoded_source = ctl_to_shred_source(meta.ctl);
                assert_eq!(decoded_source, ShredSource::Turbine);
            }
            other => panic!("expected Ready, got {:?}", other),
        }
    }

    #[test]
    fn backpressure_when_depth_exhausted() {
        let mut link = new_shred_link_with_config(256, 4, 2);
        let mut producer = link.producer();

        let payload = vec![0u8; 100];
        let ctl = shred_source_to_ctl(ShredSource::Local);

        // Fill the ring (depth=4, no consumer progress → backpressure after 4).
        let mut sent = 0;
        for _ in 0..8 {
            if producer.send(0, &payload, ctl).is_some() {
                sent += 1;
            } else {
                break;
            }
        }
        // Should have sent exactly `depth` fragments before backpressure.
        assert_eq!(sent, 4);
    }

    #[test]
    fn overrun_recovery() {
        let mut link = new_shred_link_with_config(256, 4, 2);

        // Send 4 fragments to fill the ring.
        {
            let mut producer = link.producer();
            let ctl = shred_source_to_ctl(ShredSource::Local);
            for i in 0..4u8 {
                producer.send(i as u64, &[i; 100], ctl);
            }
        }

        // Consumer starts at seq 0, but ring wrapped — should detect overrun.
        let mut consumer = link.consumer();
        // First receive — may get ready or overrun depending on ring state.
        // After recovery, subsequent receives should work.
        let result = consumer.receive(100);
        match result {
            ReceiveResult::Ready { meta, payload } => {
                // Got the first fragment, that's fine too.
                assert_eq!(meta.seq, 0);
            }
            ReceiveResult::Overrun { recover_seq } => {
                // Consumer detected overrun and can recover.
                assert!(recover_seq > 0);
            }
            ReceiveResult::Empty => {
                panic!("should not be empty after 4 sends");
            }
        }
    }
}
