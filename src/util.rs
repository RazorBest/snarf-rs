use crate::deque::DequeSliceMut;

pub const SEQ_LIM: i64 = u32::MAX as i64 + 1;

#[derive(Clone, Debug)]
pub struct CircularSeqBuffer {
    pub buffer: Vec<u8>,
    pub end: u32,
    pub seq: u32,
}

impl CircularSeqBuffer {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            buffer: vec![0u8; buffer_size],
            end: 0,
            seq: 0,
        }
    }

    pub fn set_seq(&mut self, seq: u32) {
        self.seq = seq;
    }

    pub fn seq_add(&mut self, increment: u32) {
        self.seq = self.seq.wrapping_add(increment);
    }

    pub fn seq_in_buf(&self, seq: u32) -> bool {
        let diff = (self.seq as i64 - seq as i64) % SEQ_LIM;

        (0..=self.len() as i64).contains(&diff)
    }

    pub fn seq_is_future(&self, seq: u32) -> bool {
        let diff = (seq as i64 - self.seq as i64) % SEQ_LIM;

        (1..=self.len() as i64).contains(&diff)
    }

    pub fn get_new(&mut self, next_seq: u32, data_len: usize) -> i64 {
        let mut new_data_len = (next_seq as i64 + data_len as i64 - (self.seq as i64)) % SEQ_LIM;
        if (new_data_len + self.len() as i64) % SEQ_LIM < self.len() as i64 {
            new_data_len = 0;
        }

        new_data_len
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn write_from_buffer_to_slice(&self, data: &mut [u8], seq: u32) {
        // debug_assert!(seq <= self.seq);
        let offset = self.seq.wrapping_sub(seq) as i64;
        let mut start = self.end as i64 - offset;
        let mut end = start + data.len() as i64;
        let buflen = self.len();

        if start < 0 && end < 0 {
            start += buflen as i64;
            end += buflen as i64;
        }

        if start >= 0 && end >= 0 {
            let start = start as usize;
            let end = end as usize;
            data.copy_from_slice(&self.buffer[start..end]);
        } else {
            let start = (-start) as usize;
            let end = end as usize;
            data[..start].copy_from_slice(&self.buffer[buflen - start..]);
            data[start..].copy_from_slice(&self.buffer[..end]);
        }
    }

    pub fn update_and_return_split_ref<'a>(
        &'a mut self,
        data_len: usize,
    ) -> (DequeSliceMut<'a, u8>, DequeSliceMut<'a, u8>) {
        /*
         * Assumptions: seq == self.end_seq
         * data_len <= self.buffer.len(
         * */
        let buffer_len = self.len() as u32;
        let old_end = self.end as usize;

        self.seq = self.seq.wrapping_add(data_len as u32);

        self.end += data_len as u32;
        if self.end >= buffer_len {
            self.end -= buffer_len;
        }

        let buffer = DequeSliceMut::from_slice_mut_start_at(&mut self.buffer, old_end);

        buffer.split_mut(data_len)
    }

    pub fn update(&mut self, data_len: usize) {
        /*
         * Assumptions: seq == self.end_seq
         * data.len() <= self.buffer.len(
         * */
        let buffer_len = self.buffer.len() as u32;

        // TCP data [] --> buffer
        self.seq = self.seq.wrapping_add(data_len as u32);

        self.end += data_len as u32;
        if self.end >= buffer_len {
            self.end -= buffer_len;
        }
    }

    pub fn push_data_to_buffer(&mut self, data: &[u8]) {
        let (mut write_space, _) = self.update_and_return_split_ref(data.len());
        write_space.copy_from_slice(data);
    }
}
