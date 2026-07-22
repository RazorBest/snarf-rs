use std::cmp::{Ordering, max};
use std::hash::Hash;
use std::mem;
use std::ops::{Index, IndexMut};
use std::slice::SliceIndex;
use std::time::Instant;

use crate::TransportPacketParent;
use crate::deque::{DequeSlice, DequeSliceMut};
use crate::tcp_util::{FIN_MASK, SYN_MASK, TCP_FLAGS_IDX, tcp_header_len, tcp_seq};
use crate::util::CircularSeqBuffer;

pub const TCP_SRCPORT_OFFSET: usize = 0;
pub const TCP_DSTPORT_OFFSET: usize = 2;
pub const SEQ_LIM: i64 = u32::MAX as i64 + 1;

const BUFFER_SIZE: usize = 32768;

#[derive(Debug, Clone)]
pub enum SnarfTcpError {
    PacketTooBigError,
    PacketOutsideWindow,
}
use SnarfTcpError::*;

type Result<T> = std::result::Result<T, SnarfTcpError>;

#[derive(Debug)]
pub struct FuturePacket<T> {
    /// The SEQ number of the TCP packet
    pub seq: u32,
    /// The size of the TCP header
    pub header_len: usize,
    /// Reference to the object that owns the packet and needs to know when it's consumed
    pub rf: T,
}

impl<T> PartialEq for FuturePacket<T> {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq
    }
}

impl<T> Eq for FuturePacket<T> {}

impl<T> PartialOrd for FuturePacket<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for FuturePacket<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.seq.cmp(&other.seq)
    }
}

impl<RF> FuturePacket<RF> {
    fn new(seq: u32, header_len: usize, rf: RF) -> Self {
        Self {
            seq,
            header_len,
            rf,
        }
    }
}

pub struct FutureVerdict<'a, RF>
where
    RF: TransportPacketParent,
{
    /// Reference to the object that owns the packet and needs to know when it's consumed
    pub rf: RF,
    pub header_len: usize,
    pub new_data_len: usize,
    pub writable: DequeSliceMut<'a, u8>,
}

impl<'a, RF> FutureVerdict<'a, RF>
where
    RF: TransportPacketParent,
{
    pub fn new(
        rf: RF,
        header_len: usize,
        new_data_len: usize,
        writable: DequeSliceMut<'a, u8>,
    ) -> Self {
        Self {
            rf,
            header_len,
            new_data_len,
            writable,
        }
    }

    pub fn get_data(&mut self) -> &[u8] {
        let (_, tcp_payload) = self.rf.split();

        &tcp_payload[self.header_len..]
    }
}

pub struct RemainingSpace<'a> {
    pub half1: &'a [u8],
    pub half2: &'a [u8],
}

impl<'a> RemainingSpace<'a> {
    pub fn new(half1: &'a [u8], half2: &'a [u8]) -> Self {
        Self { half1, half2 }
    }
}

pub struct WriteSpace<'a> {
    pub half1: &'a mut [u8],
    pub half2: &'a mut [u8],
}

impl<'a> WriteSpace<'a> {
    pub fn new(half1: &'a mut [u8], half2: &'a mut [u8]) -> Self {
        Self { half1, half2 }
    }
}

impl<Idx> Index<Idx> for CircularSeqBuffer
where
    Idx: SliceIndex<[u8]>,
{
    type Output = Idx::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.buffer[index]
    }
}

impl<Idx> IndexMut<Idx> for CircularSeqBuffer
where
    Idx: SliceIndex<[u8]>,
{
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        &mut self.buffer[index]
    }
}

pub type TcpTrackerUpdateResult<'a> = (
    usize,
    Option<DequeSliceMut<'a, u8>>,
    Option<DequeSlice<'a, u8>>,
);

#[derive(Debug)]
pub struct TcpPeerTracker<RF>
where
    RF: TransportPacketParent,
{
    pub first_seq: bool,
    pub fin: bool,

    pub buffer: CircularSeqBuffer,
    pub future: Vec<FuturePacket<RF>>,
}

impl<RF> TcpPeerTracker<RF>
where
    RF: TransportPacketParent,
{
    pub fn new() -> Self {
        Self {
            first_seq: false,
            fin: false,

            buffer: CircularSeqBuffer::new(BUFFER_SIZE),
            future: vec![],
        }
    }

    pub fn seq(&self) -> u32 {
        self.buffer.seq
    }

    pub fn update<'a>(
        &'a mut self,
        flags: u8,
        next_seq: u32,
        data: &mut [u8],
    ) -> Result<TcpTrackerUpdateResult<'a>> {
        if (flags & SYN_MASK) != 0 && !self.first_seq {
            self.buffer.set_seq(next_seq);
            self.buffer.seq_add(1);
            self.first_seq = true;

            return Ok((0, None, None));
        }

        if (flags & FIN_MASK) != 0 {
            self.buffer.set_seq(next_seq);
            self.buffer.seq_add(1);
            self.fin = true;
            // TODO: What if the packet has payload?
            return Ok((0, None, None));
        }

        let next_seq = next_seq as i64;

        let buffer_len = self.buffer.len() as i64;
        /*
         * S = seq of the first byte still available in the window
         * E = self.seq = seq of the first byte outside the window
         * X1 = next_seq = seq of the next packet
         * X2 = X1 + length of the data payload
         *
         * Conditions:
         * - the data payload must fit in the buffer
         * - the data payload must contain some new data
         * - the data payload should be a future packet, by skipping bytes

        Cases (assuming the first condition):
            Old data:
            .....S....X1..........X2....E........
            .....S................X1....E........
                                        ^X2
            Partial new data:
            .....S................X1....E......X2
            .....S................X1....EX2......

            Valid but unreachable case:
            X1...S......................E......X2

            All new data:
            .....S......................E......X2
                                        ^X1
            Future:
            .....S......................EX1....X2
            .....S......................E..X1..X2
        */

        let data_len = data.len() as i64;
        let curr_seq = self.buffer.seq as i64;

        // X2 - X1 <= widow_len
        if data_len > buffer_len {
            return Err(PacketTooBigError);
        }

        // 1 <= X2 - E <= window_len, otherwise it's old data or outside the window
        let new_data_len = (next_seq + data_len - curr_seq) % SEQ_LIM;
        if !(1..=buffer_len).contains(&new_data_len) {
            let right_offset = (SEQ_LIM - new_data_len) % SEQ_LIM;
            if !(0..buffer_len).contains(&right_offset) {
                return Err(PacketOutsideWindow);
            }
            // seq_end is in the window, but not next_seq
            if right_offset + data_len > buffer_len {
                return Err(PacketOutsideWindow);
            }

            self.buffer
                .write_from_buffer_to_slice(data, next_seq as u32);

            return Ok((data_len as usize, None, None));
        }

        // X1 <= E
        let old_data_len = data_len - new_data_len;
        if !(0..=buffer_len).contains(&old_data_len) {
            return Ok((0, None, None));
        }

        if old_data_len > 0 {
            self.buffer
                .write_from_buffer_to_slice(&mut data[..old_data_len as usize], next_seq as u32);
        }

        let (write_space, remaining_space) = self
            .buffer
            .update_and_return_split_ref(new_data_len as usize);

        Ok((
            old_data_len as usize,
            Some(write_space),
            Some(remaining_space.to_immutable()),
        ))
    }

    pub fn update_future_queue<'a>(&'a mut self) -> Vec<FutureVerdict<'a, RF>> {
        let start_end = self.buffer.end;

        let mut shallow_verdicts = vec![];
        let mut old_future = vec![];
        mem::swap(&mut self.future, &mut old_future);
        // Futures are sorted
        for mut packet in old_future {
            let &mut FuturePacket {
                header_len,
                seq: next_seq,
                ref mut rf,
            } = &mut packet;
            let (_, tcp_payload) = rf.split();
            let data_len = (tcp_payload.len() - header_len) as i64;

            let new_data_len = self.buffer.get_new(next_seq, data_len as usize);
            let old_data_len = data_len - new_data_len;

            // Still a future packet
            if !(0..=data_len).contains(&old_data_len) {
                self.add_future_packet(packet);
                continue;
            }
            let old_data_len = old_data_len as usize;

            if old_data_len > 0 {
                self.buffer.write_from_buffer_to_slice(
                    &mut tcp_payload[header_len..header_len + old_data_len],
                    next_seq,
                );
            }

            self.buffer.update(new_data_len as usize);

            let verdict = (packet, new_data_len as usize);
            shallow_verdicts.push(verdict);
        }

        let mut remaining =
            DequeSliceMut::from_slice_mut_start_at(&mut self.buffer.buffer, start_end as usize);
        let mut verdicts = vec![];
        for shallow_verdict in shallow_verdicts {
            let (packet, new_data_len) = shallow_verdict;
            let (write_space, new_remaining) = remaining.split_mut(new_data_len);
            remaining = new_remaining;
            let verdict =
                FutureVerdict::new(packet.rf, packet.header_len, new_data_len, write_space);
            verdicts.push(verdict);
        }

        verdicts
    }

    pub fn add_future_packet(&mut self, packet: FuturePacket<RF>) {
        self.future.push(packet);
        self.future.sort();
    }

    pub fn add_future_payload(&mut self, mut rf: RF)
    where
        RF: TransportPacketParent,
    {
        let (_, tcp_payload) = rf.split();
        let seq = tcp_seq(tcp_payload);
        let header_len = tcp_header_len(tcp_payload);

        let packet = FuturePacket::new(seq, header_len, rf);

        self.add_future_packet(packet);
    }

    pub fn get_last_written_from_buffer(&self, written: usize) -> (&[u8], &[u8]) {
        let (half1, half2) = self.buffer.buffer.split_at(self.buffer.end as usize);
        let start1 = max(half1.len(), written) - written;
        if half1.len() >= written {
            return (&half1[start1..], &half1[0..0]);
        }
        let start2 = half2.len() - (written - half1.len());

        // We go backwards
        let second = &half1[start1..];
        let first = &half2[start2..];

        (first, second)
    }
}

impl<RF> Default for TcpPeerTracker<RF>
where
    RF: TransportPacketParent,
{
    fn default() -> Self {
        Self::new()
    }
}

pub type TcpParseResult<'a> = (
    bool,
    usize,
    Option<DequeSliceMut<'a, u8>>,
    Option<DequeSlice<'a, u8>>,
);

#[derive(Debug)]
pub struct TcpSession<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord,
    RF: TransportPacketParent,
{
    pub src_net: NetAddr,
    pub src_port: u16,
    pub src_tracker: TcpPeerTracker<RF>,
    pub dst_tracker: TcpPeerTracker<RF>,
    pub src_init: bool,
    pub handshake_done: bool,
    pub created: Instant,
}

impl<NetAddr, RF> Default for TcpSession<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord + Default,
    RF: TransportPacketParent,
{
    fn default() -> Self {
        Self {
            src_net: NetAddr::default(),
            src_port: 0,
            src_tracker: TcpPeerTracker::new(),
            dst_tracker: TcpPeerTracker::new(),
            src_init: false,
            handshake_done: false,
            created: Instant::now(),
        }
    }
}

impl<NetAddr, RF> TcpSession<NetAddr, RF>
where
    NetAddr: Copy + Hash + Ord,
    RF: TransportPacketParent,
{
    pub fn read_tcp_packet<'a>(
        &'a mut self,
        src_net: NetAddr,
        src_port: u16,
        tcp_payload: &mut [u8],
    ) -> Result<TcpParseResult<'a>> {
        if !self.src_init {
            self.src_net = src_net;
            self.src_port = src_port;
            self.src_init = true;
        }

        let seq = tcp_seq(tcp_payload);
        let flags = tcp_payload[TCP_FLAGS_IDX];
        let header_len = tcp_header_len(tcp_payload);

        let data = &mut tcp_payload[header_len..];

        let is_client;

        if self.src_net == src_net && self.src_port == src_port {
            is_client = true;
            let (retransmitted, writable, remaining) = self.src_tracker.update(flags, seq, data)?;

            Ok((is_client, retransmitted, writable, remaining))
        } else {
            is_client = false;
            let (retransmitted, writable, remaining) = self.dst_tracker.update(flags, seq, data)?;

            Ok((is_client, retransmitted, writable, remaining))
        }
    }

    pub fn add_future_payload(&mut self, is_client: bool, parent_reference: RF) {
        if is_client {
            self.src_tracker.add_future_payload(parent_reference);
        } else {
            self.dst_tracker.add_future_payload(parent_reference);
        }
    }

    pub fn verdict_kept<'a>(&'a mut self, is_client: bool) -> Vec<FutureVerdict<'a, RF>> {
        if is_client {
            self.src_tracker.update_future_queue()
        } else {
            self.dst_tracker.update_future_queue()
        }
    }
}

#[cfg(test)]
mod helpers_test_tcp_peer_tracker {
    use super::*;

    impl TcpPeerTracker<Vec<u8>> {
        pub fn update_and_copy(
            &mut self,
            flags: u8,
            next_seq: u32,
            data: &[u8],
        ) -> Result<(usize, usize, Vec<u8>)> {
            const DUMMY_HEADER_LEN: usize = 21;
            let mut buf = data.to_vec();
            let (retransmitted, writable, _) = self.update(flags, next_seq, &mut buf)?;

            if let Some(mut writable) = writable {
                writable.copy_from_slice(&data[retransmitted..]);
                return Ok((retransmitted, data.len() - retransmitted, buf));
            } else if retransmitted == 0 && !data.is_empty() {
                let packet = FuturePacket::new(next_seq, DUMMY_HEADER_LEN, buf.clone());
                self.add_future_packet(packet);
            }

            Ok((retransmitted, 0, buf))
        }

        pub fn update_and_copy_assume_new(
            &mut self,
            flags: u8,
            next_seq: u32,
            data: &[u8],
        ) -> Result<usize> {
            const DUMMY_HEADER_LEN: usize = 21;
            let mut buf = data.to_vec();
            let (retransmitted, writable, _) = self.update(flags, next_seq, &mut buf)?;

            assert!(retransmitted == 0);
            assert!(buf == data);

            if let Some(mut writable) = writable {
                writable.copy_from_slice(&data[retransmitted..]);
                return Ok(data.len() - retransmitted);
            } else if retransmitted == 0 && !data.is_empty() {
                let mut tcp_payload = vec![0u8; DUMMY_HEADER_LEN];
                tcp_payload.extend_from_slice(&buf);

                let packet = FuturePacket::new(next_seq, DUMMY_HEADER_LEN, tcp_payload);
                self.add_future_packet(packet);
            }

            Ok(0)
        }
    }

    impl TransportPacketParent for Vec<u8> {
        fn split(&mut self) -> (&[u8], &mut [u8]) {
            (&[], self)
        }
    }
}

#[cfg(test)]
mod test_tcp_peer_tracker {
    use super::*;

    const BUFFER_SIZE: usize = 100;

    fn tcp_peer_tracker() -> TcpPeerTracker<Vec<u8>> {
        TcpPeerTracker {
            first_seq: false,
            fin: false,

            buffer: CircularSeqBuffer::new(BUFFER_SIZE),
            future: vec![],
        }
    }

    fn pseudorandom_data(amount: usize) -> Vec<u8> {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let counter = COUNTER.load(Ordering::Relaxed);
        COUNTER.fetch_add(amount, Ordering::Relaxed);

        (counter..counter + amount)
            .map(|x| ((x * x + 3 * x + 4) % (u8::MAX as usize)) as u8)
            .collect()
    }

    #[test]
    fn test_first_syn() {
        let mut t = tcp_peer_tracker();

        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();
        assert_eq!(t.seq(), 21)
    }

    #[test]
    fn test_first_syn_seq_wrapped() {
        let mut t = tcp_peer_tracker();

        let _ = t
            .update_and_copy_assume_new(SYN_MASK, u32::MAX, &[])
            .unwrap();
        assert_eq!(t.seq(), 0)
    }

    #[test]
    fn test_buffer() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment
        let data = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 26, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_buffer_seq_wrap() {
        let mut t = tcp_peer_tracker();
        let _ = t
            .update_and_copy_assume_new(SYN_MASK, u32::MAX - 10, &[])
            .unwrap();

        // First segment (not wrapping)
        let data = pseudorandom_data(5);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 9, &data)
            .unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment (wrapping)
        let data = pseudorandom_data(7);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 4, &data)
            .unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Third segment (not wrapping)
        let data = pseudorandom_data(3);
        let written = t.update_and_copy_assume_new(0, 2, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_buffer_reordered() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data_future = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 27, &data_future).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Third segment (before second)
        let data = pseudorandom_data(1);
        let written = t.update_and_copy_assume_new(0, 26, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment again (should be accepted now)
        let written = t.update_and_copy_assume_new(0, 27, &data_future).unwrap();
        assert_eq!(written, data_future.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data_future);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_buffer_reordered_with_overlap() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data_future = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 27, &data_future).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Third segment (before second) that overlaps with second
        let data = pseudorandom_data(3);
        let written = t.update_and_copy_assume_new(0, 26, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment again (should be accepted now, but only the new bytes)
        let (retransmitted, written, _) = t.update_and_copy(0, 27, &data_future).unwrap();
        assert_eq!(retransmitted, 2);
        assert_eq!(written, data_future.len() - 2);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data_future[2..]);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_buffer_wraps() {
        let bufsiz = BUFFER_SIZE;
        let bufsizu32 = BUFFER_SIZE as u32;

        let mut t = tcp_peer_tracker();
        t.update(SYN_MASK, 20, &mut []).unwrap();

        // First segment
        /*
         * Buf:     [.......]
         * Segment: [.......]
         * */
        let data = pseudorandom_data(bufsiz);
        let written = t.update_and_copy_assume_new(0, 21, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment
        /*
         * Buf:     [.......]
         * Segment: []
         * */
        let data = pseudorandom_data(1);
        let written = t
            .update_and_copy_assume_new(0, 21 + bufsizu32, &data)
            .unwrap();
        assert_eq!(written, 1);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Third segment
        /*
         * Buf:     [.......]
         * Segment:   [....]
         * */
        let data = pseudorandom_data(bufsiz - 2);
        let written = t
            .update_and_copy_assume_new(0, 22 + bufsizu32, &data)
            .unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Fourth segment
        /*
         * Buf:     [.......]
         * Segment: ......] [
         * */
        let data = pseudorandom_data(bufsiz - 2);
        let written = t
            .update_and_copy_assume_new(0, 20 + 2 * bufsizu32, &data)
            .unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data[..1]);
        assert_eq!(buf2, &data[1..]);
    }

    #[test]
    fn test_segment_bigger_than_buffer() {
        let mut t = tcp_peer_tracker();
        t.update(SYN_MASK, 20, &mut []).unwrap();

        // First segment
        let data = pseudorandom_data(BUFFER_SIZE + 1);
        let ret = t.update_and_copy_assume_new(0, 21, &data);
        assert!(matches!(ret, Err(PacketTooBigError)));

        // First segment, shorter
        // Seq shuoldn't change, so the entire package should be accepted
        let written = t
            .update_and_copy_assume_new(0, 21, &data[..BUFFER_SIZE])
            .unwrap();
        assert_eq!(written, BUFFER_SIZE);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data[..BUFFER_SIZE]);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_segment_retransmission() {
        let mut t = tcp_peer_tracker();
        t.update(SYN_MASK, 20, &mut []).unwrap();

        // First segment
        let data1 = pseudorandom_data(10);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment
        let data2 = pseudorandom_data(9);
        let written = t.update_and_copy_assume_new(0, 31, &data2).unwrap();
        assert_eq!(written, data2.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data2);
        assert_eq!(buf2, &[]);

        // Third segment
        let data3 = pseudorandom_data(8);
        let written = t.update_and_copy_assume_new(0, 40, &data3).unwrap();
        assert_eq!(written, data3.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data3);
        assert_eq!(buf2, &[]);

        // Second segment retransmitted
        let (retransmitted, written, _) = t.update_and_copy(0, 31, &data2).unwrap();
        assert_eq!(retransmitted, data2.len());
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // First segment retransmitted
        let (retransmitted, written, _) = t.update_and_copy(0, 21, &data1).unwrap();
        assert_eq!(retransmitted, data1.len());
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Third segment retransmitted
        let (retransmitted, written, _) = t.update_and_copy(0, 40, &data3).unwrap();
        assert_eq!(retransmitted, data3.len());
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Fourth segment
        let data4 = pseudorandom_data(8);
        let written = t.update_and_copy_assume_new(0, 48, &data4).unwrap();
        assert_eq!(written, data4.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data4);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_segment_partial_retransmission() {
        let mut t = tcp_peer_tracker();
        t.update(SYN_MASK, 20, &mut []).unwrap();

        // First segment
        let data1 = pseudorandom_data(10);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment
        let data2 = pseudorandom_data(9);
        let written = t.update_and_copy_assume_new(0, 31, &data2).unwrap();
        assert_eq!(written, data2.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data2);
        assert_eq!(buf2, &[]);

        // Second + Third segment
        let data3 = pseudorandom_data(8);
        let data: Vec<_> = data2.iter().chain(&data3).copied().collect();
        let (retransmitted, written, _) = t.update_and_copy(0, 31, &data).unwrap();
        assert_eq!(retransmitted, data2.len());
        assert_eq!(written, data3.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data3);
        assert_eq!(buf2, &[]);

        // Parts of first and second segment retransmitted
        let data: Vec<_> = data1[2..]
            .iter()
            .chain(&data2[..data2.len() - 3])
            .copied()
            .collect();
        let (retransmitted, written, _) = t.update_and_copy(0, 23, &data).unwrap();
        assert_eq!(retransmitted, data.len());
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Retransmitting first three segments plus one byte
        let data: Vec<_> = data1
            .iter()
            .chain(&data2)
            .chain(&data3)
            .chain(&[3])
            .copied()
            .collect();
        let (retransmitted, written, _) = t.update_and_copy(0, 21, &data).unwrap();
        assert_eq!(retransmitted, data1.len() + data2.len() + data3.len());
        assert_eq!(written, 1);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[3]);
        assert_eq!(buf2, &[]);

        // Fourth segment
        let data4 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 49, &data4).unwrap();
        assert_eq!(written, data4.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data4);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_segment_retransmission_rewrite() {
        let mut t = tcp_peer_tracker();
        t.update(SYN_MASK, 20, &mut []).unwrap();

        // First segment
        let data1 = pseudorandom_data(10);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment
        let data2 = pseudorandom_data(9);
        let written = t.update_and_copy_assume_new(0, 31, &data2).unwrap();
        assert_eq!(written, data2.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data2);
        assert_eq!(buf2, &[]);

        // Third segment
        let data3 = pseudorandom_data(8);
        let written = t.update_and_copy_assume_new(0, 40, &data3).unwrap();
        assert_eq!(written, data3.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data3);
        assert_eq!(buf2, &[]);

        // Second segment, but different data
        let data2_new = pseudorandom_data(data2.len());
        let (retransmitted, written, buf) = t.update_and_copy(0, 31, &data2_new).unwrap();
        assert_eq!(retransmitted, data2_new.len());
        assert_eq!(written, 0);
        assert!(data2 != data2_new);
        assert_eq!(buf, data2);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // First segment retransmitted, but different data
        let data1_new = pseudorandom_data(data1.len());
        let (retransmitted, written, buf) = t.update_and_copy(0, 21, &data1_new).unwrap();
        assert_eq!(retransmitted, data1.len());
        assert_eq!(written, 0);
        assert!(data1 != data1_new);
        assert_eq!(buf, data1);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Third segment retransmitted, but dufferent data
        let data3_new = pseudorandom_data(data3.len());
        let (retransmitted, written, buf) = t.update_and_copy(0, 40, &data3_new).unwrap();
        assert_eq!(retransmitted, data3.len());
        assert_eq!(written, 0);
        assert!(data3 != data3_new);
        assert_eq!(buf, data3);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Fourth segment
        let data4 = pseudorandom_data(8);
        let written = t.update_and_copy_assume_new(0, 48, &data4).unwrap();
        assert_eq!(written, data4.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data4);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_segment_partial_retransmission_rewrite() {
        let mut t = tcp_peer_tracker();
        t.update(SYN_MASK, 20, &mut []).unwrap();

        // First segment
        let data1 = pseudorandom_data(10);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment
        let data2 = pseudorandom_data(9);
        let written = t.update_and_copy_assume_new(0, 31, &data2).unwrap();
        assert_eq!(written, data2.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data2);
        assert_eq!(buf2, &[]);

        // Second (rewritten) + Third segment
        let data2_new = pseudorandom_data(data2.len());
        let data3 = pseudorandom_data(8);
        let data: Vec<_> = data2_new.iter().chain(&data3).copied().collect();
        let (retransmitted, written, buf) = t.update_and_copy(0, 31, &data).unwrap();
        assert_eq!(retransmitted, data2.len());
        assert_eq!(written, data3.len());
        assert!(data2 != data2_new);
        let expected: Vec<_> = data2.iter().chain(&data3).copied().collect();
        assert_eq!(buf, expected);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data3);
        assert_eq!(buf2, &[]);

        // Parts of first and second segment retransmitted, but rewrittten
        let data1_new = pseudorandom_data(data1.len());
        let data2_new = pseudorandom_data(data2.len());
        let data: Vec<_> = data1_new[2..]
            .iter()
            .chain(&data2_new[..data2_new.len() - 3])
            .copied()
            .collect();
        let (retransmitted, written, buf) = t.update_and_copy(0, 23, &data).unwrap();
        assert_eq!(retransmitted, data.len());
        assert_eq!(written, 0);
        assert!(data1 != data1_new);
        assert!(data2 != data2_new);
        let expected: Vec<_> = data1[2..]
            .iter()
            .chain(&data2[..data2.len() - 3])
            .copied()
            .collect();
        assert_eq!(buf, expected);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Retransmitting first three segments (rewritten) plus one byte
        let data1_new = pseudorandom_data(data1.len());
        let data2_new = pseudorandom_data(data2.len());
        let data3_new = pseudorandom_data(data3.len());
        let data: Vec<_> = data1_new
            .iter()
            .chain(&data2_new)
            .chain(&data3_new)
            .chain(&[3])
            .copied()
            .collect();
        let (retransmitted, written, buf) = t.update_and_copy(0, 21, &data).unwrap();
        assert_eq!(retransmitted, data1.len() + data2.len() + data3.len());
        assert_eq!(written, 1);
        assert!(data1 != data1_new);
        assert!(data2 != data2_new);
        assert!(data3 != data3_new);
        let expected: Vec<_> = data1
            .iter()
            .chain(&data2)
            .chain(&data3)
            .chain(&[3])
            .copied()
            .collect();
        assert_eq!(buf, expected);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[3]);
        assert_eq!(buf2, &[]);

        // Fourth segment
        let data4 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 49, &data4).unwrap();
        assert_eq!(written, data4.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data4);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_future_consumed() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data2 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 27, &data2).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        let verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 0);

        // 1 byte before Second segment (future)
        let data = pseudorandom_data(1);
        let written = t.update_and_copy_assume_new(0, 26, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].new_data_len, data2.len());
        let payload = verdicts[0].get_data();
        assert_eq!(payload, data2);
    }

    #[test]
    fn test_future_unconsumed() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 27, &data).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        let verdicts = t.update_future_queue();
        assert!(verdicts.is_empty());
    }

    #[test]
    fn test_future_eaten_by_next_segment() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data2 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 27, &data2).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // 1 byte + Second segment
        let data3 = pseudorandom_data(1);
        let data: Vec<_> = data3.iter().chain(&data2).copied().collect();
        let written = t.update_and_copy_assume_new(0, 26, &data).unwrap();
        assert_eq!(written, 1 + data2.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        let verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].new_data_len, 0);
    }

    #[test]
    fn test_future_eaten_by_segment_with_retransmitted() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data2 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 36, &data2).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // 2 bytes from first segment + missing bytes + Second segment
        let data3 = pseudorandom_data(10);
        let data: Vec<_> = data1[3..]
            .iter()
            .chain(&data2)
            .chain(&data3)
            .copied()
            .collect();
        let (retransmitted, written, buf) = t.update_and_copy(0, 24, &data).unwrap();
        assert_eq!(retransmitted, 2);
        assert_eq!(written, data.len() - 2);
        assert_eq!(buf, data);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data[2..]);
        assert_eq!(buf2, &[]);

        let verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].new_data_len, 0);
    }

    #[test]
    fn test_multi_future_eaten_by_segment() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Fifth segment (future)
        let data5 = pseudorandom_data(9);
        let written = t.update_and_copy_assume_new(0, 57, &data5).unwrap();
        assert_eq!(written, 0);

        // Fourth segment (future)
        let data4 = pseudorandom_data(8);
        let written = t.update_and_copy_assume_new(0, 49, &data4).unwrap();
        assert_eq!(written, 0);

        // Second segment (future)
        let data2 = pseudorandom_data(6);
        let written = t.update_and_copy_assume_new(0, 36, &data2).unwrap();
        assert_eq!(written, 0);

        // Third segment (future)
        let data3 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 42, &data3).unwrap();
        assert_eq!(written, 0);

        // missing gap + Second segment + Third segment + 1 byte of fourth segment + Fifth segment
        let data6 = pseudorandom_data(10);
        let data: Vec<_> = data6
            .iter()
            .chain(&data2)
            .chain(&data3)
            .chain(&data4[..1])
            .copied()
            .collect();
        let written = t.update_and_copy_assume_new(0, 26, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data);
        assert_eq!(buf2, &[]);

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 4);

        let v = &mut verdicts[0];
        assert_eq!(v.new_data_len, 0);
        let payload = v.get_data();
        assert_eq!(payload, data2);

        let v = &mut verdicts[1];
        assert_eq!(v.new_data_len, 0);
        let payload = v.get_data();
        assert_eq!(payload, data3);

        let v = &mut verdicts[2];
        assert_eq!(v.new_data_len, data4.len() - 1);
        let payload = v.get_data();
        assert_eq!(payload, data4);

        let v = &mut verdicts[3];
        assert_eq!(v.new_data_len, data5.len());
        let payload = v.get_data();
        assert_eq!(payload, data5);
    }

    #[test]
    fn test_futures_overlap() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data2 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 27, &data2).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Third segment (future, and overlapping with second)
        let data3 = pseudorandom_data(8);
        let data: Vec<_> = data2[data2.len() - 3..]
            .iter()
            .chain(&data3)
            .copied()
            .collect();
        let written = t.update_and_copy_assume_new(0, 31, &data).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Fourth segment (future)
        let data4 = pseudorandom_data(9);
        let written = t.update_and_copy_assume_new(0, 42, &data4).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Fifth segment (future, and overlapping with fourth)
        let data5 = pseudorandom_data(10);
        let data: Vec<_> = data4[data4.len() - 4..]
            .iter()
            .chain(&data5)
            .copied()
            .collect();
        let written = t.update_and_copy_assume_new(0, 47, &data).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // 2 bytes from first segment + missing bytes + Second segment
        let data_miss = pseudorandom_data(1);
        let data: Vec<_> = data1[3..]
            .iter()
            .chain(&data_miss)
            .chain(&data2)
            .copied()
            .collect();
        let (retransmitted, written, buf) = t.update_and_copy(0, 24, &data).unwrap();
        assert_eq!(retransmitted, 2);
        assert_eq!(written, data.len() - 2);
        assert_eq!(buf, data);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data[2..]);
        assert_eq!(buf2, &[]);

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 4);

        let v = &mut verdicts[0];
        assert_eq!(v.new_data_len, 0);
        let payload = v.get_data();
        assert_eq!(payload.len(), data2.len());

        let v = &mut verdicts[1];
        assert_eq!(v.new_data_len, data3.len());
        let payload = v.get_data();
        assert_eq!(payload.len(), 3 + data3.len());

        let v = &mut verdicts[2];
        assert_eq!(v.new_data_len, data4.len());
        let payload = v.get_data();
        assert_eq!(payload.len(), data4.len());

        let v = &mut verdicts[3];
        assert_eq!(v.new_data_len, data5.len());
        let payload = v.get_data();
        assert_eq!(payload.len(), 4 + data5.len());
    }

    #[test]
    fn test_futures_with_gaps() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data2 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 27, &data2).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Third segment (future, and overlapping with second)
        let data3 = pseudorandom_data(8);
        let data: Vec<_> = data2[data2.len() - 3..]
            .iter()
            .chain(&data3)
            .copied()
            .collect();
        let written = t.update_and_copy_assume_new(0, 31, &data).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Fourth segment (future), not connected to the third
        let data4 = pseudorandom_data(9);
        let written = t.update_and_copy_assume_new(0, 43, &data4).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Fifth segment (future, and overlapping with fourth), not connected to the fourth
        let data5 = pseudorandom_data(10);
        let written = t.update_and_copy_assume_new(0, 55, &data5).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // missing bytes + Second segment
        let data_miss = pseudorandom_data(1);
        let data: Vec<_> = data_miss.iter().chain(&data2).copied().collect();
        let written = t.update_and_copy_assume_new(0, 26, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data);
        assert_eq!(buf2, &[]);

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 2);

        let v = &mut verdicts[0];
        assert_eq!(v.new_data_len, 0);
        let payload = v.get_data();
        assert_eq!(payload.len(), data2.len());

        let v = &mut verdicts[1];
        assert_eq!(v.new_data_len, data3.len());
        let payload = v.get_data();
        assert_eq!(payload.len(), 3 + data3.len());

        // missing bytes until the fourth segment
        let data = pseudorandom_data(1);
        let written = t.update_and_copy_assume_new(0, 42, &data).unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data);
        assert_eq!(buf2, &[]);

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 1);

        let v = &mut verdicts[0];
        assert_eq!(v.new_data_len, data4.len());
        let payload = v.get_data();
        assert_eq!(payload, data4);

        // Fourth segment (retransmitted)
        let (retransmitted, written, _) = t.update_and_copy(0, 43, &data4).unwrap();
        assert_eq!(retransmitted, data4.len());
        assert_eq!(written, 0);

        let verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 0);

        // Fourth segment (retransmitted) + bytes until fifth segment
        let data_miss = pseudorandom_data(3);
        let data: Vec<_> = data4.iter().chain(&data_miss).copied().collect();
        let (retransmitted, written, _) = t.update_and_copy(0, 43, &data).unwrap();
        assert_eq!(retransmitted, data4.len());
        assert_eq!(written, data_miss.len());

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 1);

        let v = &mut verdicts[0];
        assert_eq!(v.new_data_len, data5.len());
        let payload = v.get_data();
        assert_eq!(payload, data5);
    }

    #[test]
    fn test_segment_overlapping_future() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data2 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 27, &data2).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // 1 byte + part of second segment
        let data3 = pseudorandom_data(1);
        let data: Vec<_> = data3.iter().chain(&data2[..3]).copied().collect();
        let written = t.update_and_copy_assume_new(0, 26, &data).unwrap();
        assert_eq!(written, 1 + 3);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].new_data_len, data2.len() - 3);
        let payload = verdicts[0].get_data();
        assert_eq!(payload, data2);
    }

    #[test]
    fn test_future_verdict_contains_correct_writable() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        // Second segment (future)
        let data2 = pseudorandom_data(7);
        let written = t.update_and_copy_assume_new(0, 27, &data2).unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // 1 byte
        let data3 = pseudorandom_data(1);
        let written = t.update_and_copy_assume_new(0, 26, &data3).unwrap();
        assert_eq!(written, data3.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data3);
        assert_eq!(buf2, &[]);

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 1);

        let data2_new = pseudorandom_data(data2.len());
        verdicts[0].writable.copy_from_slice(&data2_new);

        let (buf1, buf2) = t.get_last_written_from_buffer(data2.len());
        assert_eq!(buf1, data2_new);
        assert_eq!(buf2, &[]);

        let expected: Vec<_> = data1
            .iter()
            .chain(&data3)
            .chain(&data2_new)
            .copied()
            .collect();
        let (buf1, buf2) =
            t.get_last_written_from_buffer(data1.len() + data3.len() + data2_new.len());
        assert_eq!(buf1, expected);
        assert_eq!(buf2, &[]);
    }

    #[test]
    fn test_futures_outside_window() {
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(5);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data1);
        assert_eq!(buf2, &[]);

        let lim = (BUFFER_SIZE - 4) as u32;
        for i in 0..lim {
            let data = pseudorandom_data(1);
            let written = t.update_and_copy_assume_new(0, 30 + i, &data).unwrap();
            assert_eq!(written, 0);
            let (buf1, buf2) = t.get_last_written_from_buffer(written);
            assert_eq!(buf1, &[]);
            assert_eq!(buf2, &[]);
        }

        let data = pseudorandom_data(1);
        let err = t.update_and_copy_assume_new(0, 30 + lim, &data);
        assert!(matches!(err, Err(PacketOutsideWindow)));
    }

    #[test]
    fn test_seq_wrap_and_buf_overlap() {
        // This tests depends on buffer size being 100
        assert_eq!(BUFFER_SIZE, 100);

        let mut t = tcp_peer_tracker();
        let _ = t
            .update_and_copy_assume_new(SYN_MASK, u32::MAX - 201, &[])
            .unwrap();

        // First segment (not wrapping)
        let data = pseudorandom_data(100);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 200, &data)
            .unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Second segment (not wrapping)
        let data = pseudorandom_data(75);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 100, &data)
            .unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, data);
        assert_eq!(buf2, &[]);

        // Third segment (wrapping in both seq and buffer)
        let data = pseudorandom_data(60);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 25, &data)
            .unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data[..25]);
        assert_eq!(buf2, &data[25..]);
    }

    #[test]
    fn test_future_seq_wrap_and_eat_after_wrap() {
        // This tests depends on buffer size being 100
        let mut t = tcp_peer_tracker();
        let _ = t
            .update_and_copy_assume_new(SYN_MASK, u32::MAX - 11, &[])
            .unwrap();

        // First segment (not wrapping)
        let data1 = pseudorandom_data(4);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 10, &data1)
            .unwrap();
        assert_eq!(written, data1.len());

        // Second segment (future, not wrapping)
        let data2 = pseudorandom_data(2);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 5, &data2)
            .unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Third segment (future, gapped, wrapping)
        let data3 = pseudorandom_data(10);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 2, &data3)
            .unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Fourth segment, eating second, missing, and part of third
        let miss1 = pseudorandom_data(1);
        let miss2 = pseudorandom_data(1);
        let data: Vec<_> = miss1
            .iter()
            .chain(&data2)
            .chain(&miss2)
            .chain(&data3[..4])
            .copied()
            .collect();
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 6, &data)
            .unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data);
        assert_eq!(buf2, &[]);

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 2);

        let v = &mut verdicts[0];
        assert_eq!(v.new_data_len, 0);
        let payload = v.get_data();
        assert_eq!(payload, data2);

        let v = &mut verdicts[1];
        assert_eq!(v.new_data_len, data3.len() - 4);
        let payload = v.get_data();
        assert_eq!(payload, data3);
    }

    #[test]
    fn test_future_seq_wrap_and_eat_before_wrap() {
        // This tests depends on buffer size being 100
        let mut t = tcp_peer_tracker();
        let _ = t
            .update_and_copy_assume_new(SYN_MASK, u32::MAX - 15, &[])
            .unwrap();

        // First segment (not wrapping)
        let data1 = pseudorandom_data(4);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 14, &data1)
            .unwrap();
        assert_eq!(written, data1.len());

        // Second segment (future, not wrapping)
        let data2 = pseudorandom_data(2);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 9, &data2)
            .unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Third segment (future, gapped, wrapping)
        let data3 = pseudorandom_data(10);
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 6, &data3)
            .unwrap();
        assert_eq!(written, 0);
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &[]);
        assert_eq!(buf2, &[]);

        // Fourth segment, eating second, missing, and part of third
        let miss1 = pseudorandom_data(1);
        let miss2 = pseudorandom_data(1);
        let data: Vec<_> = miss1
            .iter()
            .chain(&data2)
            .chain(&miss2)
            .chain(&data3[..4])
            .copied()
            .collect();
        let written = t
            .update_and_copy_assume_new(0, u32::MAX - 10, &data)
            .unwrap();
        assert_eq!(written, data.len());
        let (buf1, buf2) = t.get_last_written_from_buffer(written);
        assert_eq!(buf1, &data);
        assert_eq!(buf2, &[]);

        let mut verdicts = t.update_future_queue();
        assert_eq!(verdicts.len(), 2);

        let v = &mut verdicts[0];
        assert_eq!(v.new_data_len, 0);
        let payload = v.get_data();
        assert_eq!(payload, data2);

        let v = &mut verdicts[1];
        assert_eq!(v.new_data_len, data3.len() - 4);
        let payload = v.get_data();
        assert_eq!(payload, data3);
    }

    #[test]
    fn test_seq_too_old() {
        // First, check the segment can be accepted, at the edge
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(4);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());

        // Second segment
        let data2 = pseudorandom_data(96);
        let written = t.update_and_copy_assume_new(0, 25, &data2).unwrap();
        assert_eq!(written, data2.len());

        // First segment retransmitted
        let (retransmitted, written, buf) = t.update_and_copy(0, 21, &data1).unwrap();
        assert_eq!(retransmitted, data1.len());
        assert_eq!(written, 0);
        assert_eq!(buf, data1);

        // Second, make the second segment one byte larger, which should be enough to make the first
        // segment outdated
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(4);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());

        // Second segment
        let data2 = pseudorandom_data(97);
        let written = t.update_and_copy_assume_new(0, 25, &data2).unwrap();
        assert_eq!(written, data2.len());

        // First segment retransmitted
        let err = t.update_and_copy(0, 21, &data1);
        assert!(matches!(err, Err(PacketOutsideWindow)))
    }

    #[test]
    fn test_seq_too_early() {
        // First, check the segment can be accepted, at the edge
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(4);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());

        // Second segment, future
        let data2 = pseudorandom_data(10);
        let written = t.update_and_copy_assume_new(0, 115, &data2).unwrap();
        assert_eq!(written, 0);

        // Second, make the second segment one byte larger, which should be enough to make the first
        // segment outdated
        let mut t = tcp_peer_tracker();
        let _ = t.update_and_copy_assume_new(SYN_MASK, 20, &[]).unwrap();

        // First segment
        let data1 = pseudorandom_data(4);
        let written = t.update_and_copy_assume_new(0, 21, &data1).unwrap();
        assert_eq!(written, data1.len());

        // Second segment, future
        let data2 = pseudorandom_data(10);
        let err = t.update_and_copy_assume_new(0, 116, &data2);
        assert!(matches!(err, Err(PacketOutsideWindow)))
    }
}
