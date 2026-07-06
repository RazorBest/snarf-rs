use std::cmp::{min, Ordering};
use std::hash::Hash;
use std::mem;
use std::time::Instant;
use std::collections::VecDeque;

pub const TCP_SRCPORT_OFFSET: usize = 0;
pub const TCP_DSTPORT_OFFSET: usize = 2;
pub const TCP_SEQ_OFFSET: usize = 4;
pub const TCP_DATAOFFSET_IDX: usize = 12;
pub const TCP_SYN_IDX: usize = 13;
pub const TCP_FIN_IDX: usize = 13;

// The maximum expected size of the tcp buffer of the client or server
const MAX_WINDOW_SIZE: i64 = 4194304;

#[derive(Debug, Eq)]
struct BufferedPacket {
    seq: u32,
    /// The TCP payload bytes
    payload: Vec<u8>,
}

impl PartialEq for BufferedPacket {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}

impl PartialOrd for BufferedPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.seq.partial_cmp(&other.seq)
    }
}

impl Ord for BufferedPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        self.seq.cmp(&other.seq)
    }
}

impl BufferedPacket {
    fn new(tcp_segment: &[u8]) -> Self {
        let p = tcp_segment;
        let seq = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        let data_offset = (p[TCP_DATAOFFSET_IDX] >> 4) as usize;
        let header_len = data_offset * 4;

        Self {
            seq,
            payload: p[header_len..].to_vec(),
        }
    }

    fn merge_into_vec(buf_vec: &Vec<&BufferedPacket>) -> Vec<u8> {
        buf_vec.iter().fold(vec![], |mut acc, packet| {
            acc.extend_from_slice(&packet.payload);
            acc
        })
    }
}

struct TcpPeerTracker {
    first_seq: bool,
    seq: u32,
    fin: bool,
    prev_len: u32,
    // Assumption: the packets in the queue are ordered
    buffers: VecDeque<BufferedPacket>,
    seq_before_wrap: Option<u32>,
    sent: u64,

    // Better buffer
    buffer: Vec<u8>,
    end: u32,
    seq_end: u32,
    blen: u32,
    future: Vec<BufferedPacket>
}

impl TcpPeerTracker {
    fn new() -> Self {
        Self {
            first_seq: false,
            seq: 0,
            fin: false,
            prev_len: 0,
            buffers: VecDeque::new(),
            seq_before_wrap: None,
            sent: 0,

            buffer: vec![],
            end: 0,
            seq_end: 0,
            blen: 0,
            future: vec![],
        }
    }

    fn update(
        &mut self,
        syn: bool,
        fin: bool,
        new_seq: u32,
        new_len: u32,
    ) -> Result<(bool, bool), String> {
        let mut retransmission = false;
        let mut future = false;
        if syn && !self.first_seq {
            self.seq = new_seq.wrapping_add(1);
            self.seq_end = self.seq;
            self.prev_len = new_len;
            self.first_seq = true;
            return Ok((retransmission, future));
        }

        if fin {
            self.seq = new_seq.wrapping_add(1);
            self.prev_len = new_len;
            self.fin = true;
            // TODO: What if the packet has payload?
            return Ok((retransmission, future));
        }

        let new_seq = new_seq as i64;
        let self_seq = self.seq as i64;
        let prev_len = self.prev_len as i64;

        if (1..=MAX_WINDOW_SIZE).contains(&(self_seq + prev_len - new_seq + (u32::MAX as i64)))
            || (1..=MAX_WINDOW_SIZE).contains(&(self_seq + prev_len - new_seq))
        {
            retransmission = true;
            return Ok((retransmission, future));
        }

        // If the seq is ahead (but not too much), it might mean that this is a reordered packet
        if (1..=MAX_WINDOW_SIZE).contains(&((new_seq + u32::MAX as i64) - (self_seq + prev_len)))
            || (1..=MAX_WINDOW_SIZE).contains(&(new_seq - (self_seq + prev_len)))
        {
            future = true;
            return Ok((retransmission, future));
        }

        if (self_seq as u32).wrapping_add(prev_len as u32) != (new_seq as u32) {
            return Err("Seq doesn't match the expected value".to_string());
        }

        self.seq = new_seq as u32;
        self.prev_len = new_len;

        Ok((retransmission, future))
    }

    fn add_sent_packet(&mut self, tcp_segment: &[u8]) {
        let packet = BufferedPacket::new(tcp_segment);
        // If a wrap-around is triggered
        if self.buffers.len() > 0 && self.buffers[self.buffers.len() - 1].seq > packet.seq {
            self.seq_before_wrap = Some(self.buffers[self.buffers.len() - 1].seq);
        }
        self.buffers.push_back(packet);
    }

    fn add_future_packet(&mut self, packet: BufferedPacket) {
        self.future.push(packet); 
        self.future.sort();
    }

    fn push_data_to_buffer(&mut self, data: &[u8]) {
        /*
         * Assumptions: seq == self.end_seq
         * data.len() <= self.buffer.len()
         * */
        let data_len = data.len();
        let buffer_len = self.buffer.len();

        // TCP data [] --> buffer
        // One half
        let write_start = self.end as usize;
        let copy_len = min(data_len, buffer_len - write_start);

        self.buffer[write_start..write_start+copy_len].copy_from_slice(&data[..copy_len]);

        self.end += copy_len as u32;
        debug_assert!(self.end <= buffer_len as u32);
        if self.end == buffer_len as u32 {
            self.end = 0;
        }

        // Second half, always starting to write from 0 (queue wrap-up)
        if copy_len < data_len {
            let data2 = &data[copy_len..];
            let copy_len2 = data_len - copy_len;

            let write_start = self.end as usize;
            self.buffer[write_start..write_start+copy_len2].copy_from_slice(&data2);

            self.end += copy_len2 as u32;
            debug_assert!(self.end < buffer_len as u32);
        }
        self.seq_end = self.seq_end.wrapping_add(data_len as u32);
    }

    pub fn add_sent_packet_new(&mut self, tcp_segment: &[u8]) {
        const SEQ_LIM: i64 = u32::MAX as i64 + 1;
        let seq = {
            let p = tcp_segment;
            u32::from_be_bytes([p[4], p[5], p[6], p[7]]) as i64
        };
        let data = {
            let data_offset = (tcp_segment[TCP_DATAOFFSET_IDX] >> 4) as i64;
            let header_len = (data_offset * 4) as usize;
            &tcp_segment[header_len..]
        };
        let data_len = data.len() as i64;
        /*
         * end = index of first writtable byte
         * seq_end = seq of first writtable byte
         * blen = the length of the filled buffer
         * seq_start = seq_end - blen (the first written byte still available)
         *
         * seq_end = 3
         * blen = 2
         * seq_start = 1
         *
         * If the buffer is empty, blen = 0. At the beginning, end = 0.
         *
         * [ AAAAAAAAAAAAAAAAAAA ] 00000000000000000000000000000
         * ^                       ^
         * CCCCCC ] AAAAAAAAAAAAAAAAAAA ] [ BBBBBBBBBBBB ] [ CCCCCCCCCCCCCCCCCC
         *         ^
         *         ^
         * */

        /*
        S......................X1..E....X2
   X1...S..........................E....X2
        S..........................E....X2
                                   ^X1
        S.................................E

        S....X2.................X1....E    
                                     S......

        E - X2 = you get something small
        X1 <= E

        end_seq seq + data_len
        */

        let buffer_len = self.buffer.len() as i64;

        // X2 - X1 <= widow_len
        if data_len > buffer_len {
            return
        }

        // 0 <= X2 - E <= window_len / 2
        let new_data_len = (seq + data_len - (self.seq_end as i64)) % SEQ_LIM;
        if !(1..=buffer_len).contains(&new_data_len) {
            return
        }

        // X1 <= E
        let old_data_len = data_len - new_data_len;
        if !(0..=buffer_len).contains(&old_data_len) {
            let packet = BufferedPacket::new(tcp_segment);
            self.add_future_packet(packet);
            return;
        }

        // TCP data [] --> buffer
        // One half
        self.push_data_to_buffer(&data[(old_data_len as usize)..]);

        let mut old_future = vec![];
        mem::swap(&mut self.future, &mut old_future);
        let future_len = self.future.len();
        // Futures are sorted
        for packet in old_future {
            let old_data_len = ((self.seq_end as i64) - (packet.seq as i64)) % SEQ_LIM;
            if old_data_len > buffer_len {
                self.future.push(packet);
                continue;
            }

            let new_data_len = ((packet.seq as i64) + (packet.payload.len() as i64) - (self.seq_end as i64)) % SEQ_LIM;
            if !(1..=buffer_len).contains(&new_data_len) {
                // Don't put the packet back. It's not future anymore
                continue;
            }

            self.push_data_to_buffer(&packet.payload[(old_data_len as usize)..]);
        }
    }

    fn clear_old_packets_from_buffers(&mut self) {
        if self.buffers.len() == 0 {
            return;
        }
        let last_seq = if let Some(seq_before_wrap) = self.seq_before_wrap {
            seq_before_wrap as i64 + self.buffers[self.buffers.len() - 1].seq as i64
        } else {
            self.buffers[self.buffers.len() - 1].seq as i64
        };

        // TODO: partially delete buffers, because we might delete too much now
        let cutoff = self
            .buffers
            .iter()
            .position(|packet| last_seq - (packet.seq as i64) > MAX_WINDOW_SIZE)
            .unwrap_or(0);
        self.buffers.drain(..cutoff);
    }

    fn search_packets_in_bufs<'a>(
        &'a self,
        mut seq: u32,
        mut payload_len: usize,
    ) -> Option<Vec<&'a BufferedPacket>> {
        let mut found_packets: Vec<&'a BufferedPacket> = vec![];
        for packet in self.buffers.iter() {
            let packet_seq = packet.seq;
            if packet_seq == seq {
                found_packets.push(packet);
                payload_len -= packet.payload.len();
                seq = seq.wrapping_add(packet.payload.len() as u32);
            }

            if payload_len <= 0 {
                break;
            }
        }

        if payload_len != 0 {
            return None;
        }

        Some(found_packets)
    }
}


pub struct TcpSession<NetAddr>
where
    NetAddr: Copy + Hash + Ord
{
    pub src_net: NetAddr,
    pub src_port: u16,
    pub src_tracker: TcpPeerTracker,
    pub dst_tracker: TcpPeerTracker,
    pub src_init: bool,
    pub handshake_done: bool,
    // state: T,
    pub created: Instant,
}

impl<NetAddr> Default for TcpSession<NetAddr>
where
    NetAddr: Copy + Hash + Ord + Default
{
    fn default() -> Self {
        Self {
            src_net: NetAddr::default(),
            src_port: 0,
            src_tracker: TcpPeerTracker::new(),
            dst_tracker: TcpPeerTracker::new(),
            src_init: false,
            handshake_done: false,
            // state: T::default(),
            created: Instant::now(),
        }
    }
}

impl<NetAddr>/*<T: Default>*/ TcpSession<NetAddr>/*<T>*/
where
    NetAddr: Copy + Hash + Ord
{
    pub fn read_tcp_packet<'a>(
        &mut self,
        src_net: NetAddr,
        src_port: u16,
        tcp_payload: &[u8],
    ) -> Result<(bool, Option<Vec<u8>>, bool), String> {
        if !self.src_init {
            self.src_net = src_net;
            self.src_port = src_port;
            self.src_init = true;
        }

        let seq = u32::from_be_bytes([tcp_payload[TCP_SEQ_OFFSET], tcp_payload[TCP_SEQ_OFFSET + 1], tcp_payload[TCP_SEQ_OFFSET + 2], tcp_payload[TCP_SEQ_OFFSET + 3]]);
        let syn = ((tcp_payload[TCP_SYN_IDX] >> 1) & 0x1) == 1;
        let fin = (tcp_payload[TCP_FIN_IDX] & 0x1) == 1;
        let header_len = (tcp_payload[TCP_DATAOFFSET_IDX] >> 4) as usize * 4;
        let payload_len = tcp_payload.len() - header_len;

        let is_client;
        let retransmission: bool;
        let future: bool;

        if self.src_net == src_net && self.src_port == src_port {
            is_client = true;
            (retransmission, future) = self.src_tracker.update(syn, fin, seq, payload_len as u32)?;
            self.src_tracker.sent += tcp_payload.len() as u64;
        } else {
            is_client = false;
            (retransmission, future) = self.dst_tracker.update(syn, fin, seq, payload_len as u32)?;
            self.dst_tracker.sent += tcp_payload.len() as u64;
        }

        if payload_len == 0 || !retransmission || future {
            return Ok((is_client, None, future));
        }

        let buf_vec = if is_client {
            self.src_tracker
                .search_packets_in_bufs(seq, payload_len)
        } else {
            self.dst_tracker
                .search_packets_in_bufs(seq, payload_len)
        };

        let buf_vec = match buf_vec {
            Some(b) => b,
            // TODO: future was forced to true so the interceptor can drop the packet;
            None => {
                return Ok((is_client, None, true));
            }
        };

        let reconstructed_payload = BufferedPacket::merge_into_vec(&buf_vec);

        Ok((is_client, Some(reconstructed_payload), future))
    }

    pub fn add_sent_packet(&mut self, src_net: NetAddr, src_port: u16, tcp_segment: &[u8]) {
        if src_net == self.src_net && src_port == self.src_port {
            self.src_tracker.add_sent_packet(tcp_segment);
        } else {
            self.dst_tracker.add_sent_packet(tcp_segment);
        }

        self.clear_old_packets_from_buffers();
    }

    pub fn clear_old_packets_from_buffers(&mut self) {
        self.src_tracker.clear_old_packets_from_buffers();
        self.dst_tracker.clear_old_packets_from_buffers();
    }
}
