/// Wire format types for Ethernet, IPv4, and UDP headers.
///
/// All headers use host byte order internally with explicit conversion
/// during encode/decode. This matches Firedancer's approach of parsing
/// into host-order structs for fast field access.
use paradencer_constants::network;

// ---------------------------------------------------------------------------
// Ethernet header
// ---------------------------------------------------------------------------

/// Parsed Ethernet frame header (14 bytes on wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    pub const WIRE_SIZE: usize = network::ETHERNET_HEADER_SIZE;

    /// Decode an Ethernet header from a byte slice.
    /// Returns `None` if the slice is too short.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_SIZE {
            return None;
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&buf[0..6]);
        src_mac.copy_from_slice(&buf[6..12]);
        let ether_type = u16::from_be_bytes([buf[12], buf[13]]);
        Some(Self {
            dst_mac,
            src_mac,
            ether_type,
        })
    }

    /// Encode the header into a byte slice.
    /// Returns the number of bytes written (always 14).
    /// Panics if `buf.len() < 14`.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        assert!(buf.len() >= Self::WIRE_SIZE);
        buf[0..6].copy_from_slice(&self.dst_mac);
        buf[6..12].copy_from_slice(&self.src_mac);
        buf[12..14].copy_from_slice(&self.ether_type.to_be_bytes());
        Self::WIRE_SIZE
    }
}

// ---------------------------------------------------------------------------
// IPv4 header
// ---------------------------------------------------------------------------

/// Parsed IPv4 header (20 bytes on wire, no options).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

impl Ipv4Header {
    pub const WIRE_SIZE: usize = network::IPV4_HEADER_SIZE;

    /// Create a new IPv4 header with common defaults.
    pub fn new(protocol: u8, src_addr: u32, dst_addr: u32, payload_len: u16) -> Self {
        Self {
            version_ihl: (network::IPV4_VERSION << 4) | network::IPV4_DEFAULT_IHL,
            dscp_ecn: 0,
            total_length: Self::WIRE_SIZE as u16 + payload_len,
            identification: 0,
            flags_fragment: network::IPV4_FLAG_DF,
            ttl: network::IPV4_DEFAULT_TTL,
            protocol,
            checksum: 0, // Computed after encode
            src_addr,
            dst_addr,
        }
    }

    /// Decode an IPv4 header from a byte slice.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_SIZE {
            return None;
        }
        Some(Self {
            version_ihl: buf[0],
            dscp_ecn: buf[1],
            total_length: u16::from_be_bytes([buf[2], buf[3]]),
            identification: u16::from_be_bytes([buf[4], buf[5]]),
            flags_fragment: u16::from_be_bytes([buf[6], buf[7]]),
            ttl: buf[8],
            protocol: buf[9],
            checksum: u16::from_be_bytes([buf[10], buf[11]]),
            src_addr: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            dst_addr: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
        })
    }

    /// Encode the header into a byte slice. Does NOT compute the checksum.
    /// Call `compute_checksum()` after encoding to fill in the checksum field.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        assert!(buf.len() >= Self::WIRE_SIZE);
        buf[0] = self.version_ihl;
        buf[1] = self.dscp_ecn;
        buf[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identification.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags_fragment.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        buf[12..16].copy_from_slice(&self.src_addr.to_be_bytes());
        buf[16..20].copy_from_slice(&self.dst_addr.to_be_bytes());
        Self::WIRE_SIZE
    }

    /// Encode the header and compute the checksum in-place.
    pub fn encode_with_checksum(&mut self, buf: &mut [u8]) -> usize {
        self.checksum = 0;
        self.encode(buf);
        self.checksum = ipv4_checksum(&buf[..Self::WIRE_SIZE]);
        buf[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        Self::WIRE_SIZE
    }

    /// Returns the IP header length in bytes (from IHL field).
    #[inline]
    pub fn header_len(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }

    /// Returns the IP version (should be 4).
    #[inline]
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    /// Returns the payload length (total_length - header_len).
    #[inline]
    pub fn payload_len(&self) -> u16 {
        self.total_length.saturating_sub(self.header_len() as u16)
    }

    /// Verify the header checksum. Returns true if valid.
    pub fn verify_checksum(&self, buf: &[u8]) -> bool {
        if buf.len() < Self::WIRE_SIZE {
            return false;
        }
        ipv4_checksum(&buf[..Self::WIRE_SIZE]) == 0
    }
}

/// Compute the IPv4 header checksum (RFC 1071).
///
/// The checksum is the one's complement of the one's complement sum
/// of all 16-bit words in the header.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------
// UDP header
// ---------------------------------------------------------------------------

/// Parsed UDP header (8 bytes on wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub const WIRE_SIZE: usize = network::UDP_HEADER_SIZE;

    /// Create a new UDP header.
    pub fn new(src_port: u16, dst_port: u16, payload_len: u16) -> Self {
        Self {
            src_port,
            dst_port,
            length: Self::WIRE_SIZE as u16 + payload_len,
            checksum: 0, // Optional for IPv4
        }
    }

    /// Decode a UDP header from a byte slice.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::WIRE_SIZE {
            return None;
        }
        Some(Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            length: u16::from_be_bytes([buf[4], buf[5]]),
            checksum: u16::from_be_bytes([buf[6], buf[7]]),
        })
    }

    /// Encode the header into a byte slice.
    pub fn encode(&self, buf: &mut [u8]) -> usize {
        assert!(buf.len() >= Self::WIRE_SIZE);
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..6].copy_from_slice(&self.length.to_be_bytes());
        buf[6..8].copy_from_slice(&self.checksum.to_be_bytes());
        Self::WIRE_SIZE
    }

    /// Returns the payload length (length field - header size).
    #[inline]
    pub fn payload_len(&self) -> u16 {
        self.length.saturating_sub(Self::WIRE_SIZE as u16)
    }
}

/// Parse a complete UDP/IPv4/Ethernet packet, returning all three headers
/// and a slice to the UDP payload.
///
/// Returns `None` if the packet is malformed or too short.
pub fn parse_udp_packet(buf: &[u8]) -> Option<(EthernetHeader, Ipv4Header, UdpHeader, &[u8])> {
    let eth = EthernetHeader::decode(buf)?;
    if eth.ether_type != network::ETHERTYPE_IPV4 {
        return None;
    }

    let ip_start = EthernetHeader::WIRE_SIZE;
    let ip = Ipv4Header::decode(buf.get(ip_start..)?)?;
    if ip.version() != 4 || ip.protocol != network::IPV4_PROTO_UDP {
        return None;
    }

    let udp_start = ip_start + ip.header_len();
    let udp = UdpHeader::decode(buf.get(udp_start..)?)?;

    let payload_start = udp_start + UdpHeader::WIRE_SIZE;
    let payload_end = (udp_start + udp.length as usize).min(buf.len());
    let payload = buf.get(payload_start..payload_end)?;

    Some((eth, ip, udp, payload))
}

/// Build a complete UDP/IPv4/Ethernet packet into `buf`.
///
/// Returns the total number of bytes written, or `None` if `buf` is too small.
pub fn build_udp_packet(
    buf: &mut [u8],
    eth: &EthernetHeader,
    ip: &mut Ipv4Header,
    udp: &UdpHeader,
    payload: &[u8],
) -> Option<usize> {
    let total =
        EthernetHeader::WIRE_SIZE + Ipv4Header::WIRE_SIZE + UdpHeader::WIRE_SIZE + payload.len();
    if buf.len() < total {
        return None;
    }

    let mut offset = 0;
    offset += eth.encode(&mut buf[offset..]);
    offset += ip.encode_with_checksum(&mut buf[offset..]);
    offset += udp.encode(&mut buf[offset..]);
    buf[offset..offset + payload.len()].copy_from_slice(payload);
    offset += payload.len();

    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_roundtrip() {
        let hdr = EthernetHeader {
            dst_mac: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ether_type: network::ETHERTYPE_IPV4,
        };
        let mut buf = [0u8; 14];
        hdr.encode(&mut buf);
        let decoded = EthernetHeader::decode(&buf).unwrap();
        assert_eq!(hdr, decoded);
    }

    #[test]
    fn ethernet_too_short() {
        assert!(EthernetHeader::decode(&[0u8; 13]).is_none());
    }

    #[test]
    fn ipv4_roundtrip() {
        let hdr = Ipv4Header::new(
            network::IPV4_PROTO_UDP,
            0x0A000001, // 10.0.0.1
            0x0A000002, // 10.0.0.2
            100,
        );
        let mut buf = [0u8; 20];
        hdr.encode(&mut buf);
        let decoded = Ipv4Header::decode(&buf).unwrap();
        assert_eq!(decoded.version(), 4);
        assert_eq!(decoded.header_len(), 20);
        assert_eq!(decoded.protocol, network::IPV4_PROTO_UDP);
        assert_eq!(decoded.src_addr, 0x0A000001);
        assert_eq!(decoded.dst_addr, 0x0A000002);
        assert_eq!(decoded.total_length, 120);
        assert_eq!(decoded.payload_len(), 100);
    }

    #[test]
    fn ipv4_checksum_computation() {
        let mut hdr = Ipv4Header::new(network::IPV4_PROTO_UDP, 0xC0A80001, 0xC0A80002, 50);
        let mut buf = [0u8; 20];
        hdr.encode_with_checksum(&mut buf);
        // Verify the checksum is correct
        assert!(hdr.verify_checksum(&buf));
        // Corrupt a byte and verify it fails
        buf[5] ^= 0xFF;
        assert!(!hdr.verify_checksum(&buf));
    }

    #[test]
    fn ipv4_too_short() {
        assert!(Ipv4Header::decode(&[0u8; 19]).is_none());
    }

    #[test]
    fn udp_roundtrip() {
        let hdr = UdpHeader::new(8000, 9000, 256);
        let mut buf = [0u8; 8];
        hdr.encode(&mut buf);
        let decoded = UdpHeader::decode(&buf).unwrap();
        assert_eq!(hdr, decoded);
        assert_eq!(decoded.src_port, 8000);
        assert_eq!(decoded.dst_port, 9000);
        assert_eq!(decoded.payload_len(), 256);
    }

    #[test]
    fn udp_too_short() {
        assert!(UdpHeader::decode(&[0u8; 7]).is_none());
    }

    #[test]
    fn parse_full_udp_packet() {
        // Build a complete Ethernet/IPv4/UDP packet
        let payload = b"hello";
        let eth = EthernetHeader {
            dst_mac: [0x01; 6],
            src_mac: [0x02; 6],
            ether_type: network::ETHERTYPE_IPV4,
        };
        let mut ip = Ipv4Header::new(
            network::IPV4_PROTO_UDP,
            0x7F000001,
            0x7F000002,
            UdpHeader::WIRE_SIZE as u16 + payload.len() as u16,
        );
        let udp = UdpHeader::new(1234, 5678, payload.len() as u16);

        let mut buf = [0u8; 256];
        let total = build_udp_packet(&mut buf, &eth, &mut ip, &udp, payload).unwrap();

        // Parse it back
        let (eth2, ip2, udp2, data) = parse_udp_packet(&buf[..total]).unwrap();
        assert_eq!(eth2.dst_mac, [0x01; 6]);
        assert_eq!(ip2.src_addr, 0x7F000001);
        assert_eq!(ip2.dst_addr, 0x7F000002);
        assert_eq!(udp2.src_port, 1234);
        assert_eq!(udp2.dst_port, 5678);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn build_udp_packet_too_small() {
        let eth = EthernetHeader {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            ether_type: network::ETHERTYPE_IPV4,
        };
        let mut ip = Ipv4Header::new(network::IPV4_PROTO_UDP, 0, 0, 8);
        let udp = UdpHeader::new(0, 0, 0);
        let mut buf = [0u8; 10]; // Too small
        assert!(build_udp_packet(&mut buf, &eth, &mut ip, &udp, &[]).is_none());
    }

    #[test]
    fn ipv4_checksum_rfc1071_example() {
        // Known good checksum test: all zeros header should produce 0xFFFF checksum
        let zeros = [0u8; 20];
        let cksum = ipv4_checksum(&zeros);
        assert_eq!(cksum, 0xFFFF);
    }

    #[test]
    fn parse_non_ipv4_returns_none() {
        let mut buf = [0u8; 64];
        let eth = EthernetHeader {
            dst_mac: [0; 6],
            src_mac: [0; 6],
            ether_type: network::ETHERTYPE_ARP, // Not IPv4
        };
        eth.encode(&mut buf);
        assert!(parse_udp_packet(&buf).is_none());
    }

    #[test]
    fn ipv4_flags_df_set() {
        let hdr = Ipv4Header::new(network::IPV4_PROTO_UDP, 0, 0, 0);
        assert_eq!(
            hdr.flags_fragment & network::IPV4_FLAG_DF,
            network::IPV4_FLAG_DF
        );
    }
}
