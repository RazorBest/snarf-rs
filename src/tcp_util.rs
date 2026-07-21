use crate::ipv4_util::{ipv4_header_len, ipv4_total_len};

pub const TCP_DATAOFFSET_IDX: usize = 12;
pub const TCP_FLAGS_IDX: usize = 13;
pub const TCP_SEQ_OFFSET: usize = 4;
pub const SYN_MASK: u8 = 0x2;
pub const FIN_MASK: u8 = 0x1;

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
pub fn tcp_ipv4_data_len(ipv4_payload: &[u8]) -> usize {
    let iphlen = ipv4_header_len(ipv4_payload) as usize;
    let total_len = ipv4_total_len(ipv4_payload) as usize;
    let thlen = tcp_header_len(&ipv4_payload[iphlen..]);

    total_len - iphlen - thlen
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
