use crate::ipv4_util::{
    ipv4_checksum, ipv4_dst_ip, ipv4_header_len, ipv4_split, ipv4_src_ip, ipv4_total_len,
};

pub const TCP_SRCPORT_OFFSET: usize = 0;
pub const TCP_DSTPORT_OFFSET: usize = 2;
pub const TCP_DATAOFFSET_IDX: usize = 12;
pub const TCP_FLAGS_IDX: usize = 13;
pub const TCP_SEQ_OFFSET: usize = 4;
pub const FIN_MASK: u8 = 0x1;
pub const SYN_MASK: u8 = 0x2;
pub const RST_MASK: u8 = 0x4;

#[inline(always)]
pub fn tcp_header_len(tcp_payload: &[u8]) -> usize {
    (tcp_payload[TCP_DATAOFFSET_IDX] >> 4) as usize * 4
}

#[inline(always)]
pub fn tcp_seq(tcp_payload: &[u8]) -> u32 {
    u32::from_be_bytes([
        tcp_payload[TCP_SEQ_OFFSET],
        tcp_payload[TCP_SEQ_OFFSET + 1],
        tcp_payload[TCP_SEQ_OFFSET + 2],
        tcp_payload[TCP_SEQ_OFFSET + 3],
    ])
}

#[inline(always)]
pub fn tcp_src_port(tcp_payload: &[u8]) -> u16 {
    u16::from_be_bytes([
        tcp_payload[TCP_SRCPORT_OFFSET],
        tcp_payload[TCP_SRCPORT_OFFSET + 1],
    ])
}

#[inline(always)]
pub fn tcp_dst_port(tcp_payload: &[u8]) -> u16 {
    u16::from_be_bytes([
        tcp_payload[TCP_DSTPORT_OFFSET],
        tcp_payload[TCP_DSTPORT_OFFSET + 1],
    ])
}

#[inline(always)]
pub fn tcp_ipv4_session_pair(ipv4_payload: &[u8]) -> (([u8; 4], u16), ([u8; 4], u16)) {
    let src_ip = ipv4_src_ip(ipv4_payload);
    let dst_ip = ipv4_dst_ip(ipv4_payload);
    let (_ip_header, tcp_payload) = ipv4_split(ipv4_payload);
    let src_port = tcp_src_port(tcp_payload);
    let dst_port = tcp_dst_port(tcp_payload);

    ((src_ip, src_port), (dst_ip, dst_port))
}

#[inline(always)]
pub fn tcp_ipv4_data_len(ipv4_payload: &[u8]) -> usize {
    let iphlen = ipv4_header_len(ipv4_payload) as usize;
    let total_len = ipv4_total_len(ipv4_payload) as usize;
    let thlen = tcp_header_len(&ipv4_payload[iphlen..]);

    total_len - iphlen - thlen
}

#[inline(always)]
pub fn tcp_ipv4_syn(ipv4_payload: &[u8]) -> bool {
    let iphlen = ipv4_header_len(ipv4_payload) as usize;

    tcp_syn(&ipv4_payload[iphlen..])
}

#[inline(always)]
pub fn tcp_ipv4_seq(ipv4_payload: &[u8]) -> u32 {
    let iphlen = ipv4_header_len(ipv4_payload) as usize;

    tcp_seq(&ipv4_payload[iphlen..])
}

#[inline(always)]
pub fn tcp_flags(tcp_payload: &[u8]) -> u8 {
    tcp_payload[TCP_FLAGS_IDX]
}

#[inline(always)]
pub fn tcp_syn(tcp_payload: &[u8]) -> bool {
    tcp_flags(tcp_payload) & SYN_MASK != 0
}

#[inline(always)]
pub fn tcp_fin(tcp_payload: &[u8]) -> bool {
    tcp_flags(tcp_payload) & FIN_MASK != 0
}

#[inline(always)]
pub fn update_checksum_tcp_ipv4(ip_header: &[u8], tcp_payload: &mut [u8]) {
    tcp_payload[16..18].copy_from_slice(&[0, 0]);
    let new_checksum = ipv4_checksum(
        tcp_payload,
        ip_header[12..16].try_into().unwrap(),
        ip_header[16..20].try_into().unwrap(),
    );
    tcp_payload[16..18].copy_from_slice(&new_checksum.to_be_bytes());
}

#[cfg(test)]
mod test_tcp_util {
    use super::*;

    macro_rules! from_hex {
        ($hex:expr) => {{
            let s = $hex;
            assert!(s.len() % 2 == 0);
            s.as_bytes()
                .chunks_exact(2)
                .map(|c| {
                    let s = std::str::from_utf8(c).unwrap();
                    u8::from_str_radix(s, 16).unwrap()
                })
                .collect::<Vec<u8>>()
        }};
    }

    #[test]
    fn test_update_checksum_tcp_ipv4() {
        let ip_header = from_hex!("4500003c572e40004006e58b7f0000017f000001");
        let mut tcp_payload = from_hex!(
            "d36420fc958a199a00000000a002ffd7876500000204ffd70402080ac8fd22cd0000000001030307"
        );
        // --------------------------------------------------------- ^^^^ This checksum is wrong/outdated

        assert_ne!(tcp_payload[16..18], [0xc0, 0xb1]);

        update_checksum_tcp_ipv4(&ip_header, &mut tcp_payload);
        assert_eq!(tcp_payload[16..18], [0xc0, 0xb1]);
    }
}
