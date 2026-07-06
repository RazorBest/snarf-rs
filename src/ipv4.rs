/// Calculate the checksum for a packet built on IPv4. Used by UDP and TCP.
pub fn ipv4_checksum(data: &[u8], source: [u8; 4], destination: [u8; 4]) -> u16 {
    let skipword = 8;
    let mut sum = 0u32;

    // Checksum pseudo-header
    sum += ipv4_word_sum(source);
    sum += ipv4_word_sum(destination);

    // Specific to TCP, same as the Protocol field in the IP header, specified in RFC790
    let next_level_protocol: u32 = 6;
    sum += next_level_protocol;

    let len = data.len();
    sum += len as u32;

    // Checksum packet header and data
    sum += sum_be_words(data, skipword);

    finalize_checksum(sum)
}

pub fn ipv4_word_sum(ip: [u8; 4]) -> u32 {
    ((ip[0] as u32) << 8 | ip[1] as u32) + ((ip[2] as u32) << 8 | ip[3] as u32)
}

/// Sum all words (16 bit chunks) in the given data. The word at word offset
/// `skipword` will be skipped. Each word is treated as big endian.
pub fn sum_be_words(data: &[u8], skipword: usize) -> u32 {
    if data.len() == 0 {
        return 0;
    }
    let len = data.len();
    let mut cur_data = &data[..];
    let mut sum = 0u32;
    let mut i = 0;
    while cur_data.len() >= 2 {
        if i != skipword {
            // It's safe to unwrap because we verified there are at least 2 bytes
            sum += u16::from_be_bytes(cur_data[0..2].try_into().unwrap()) as u32;
        }
        cur_data = &cur_data[2..];
        i += 1;
    }

    // If the length is odd, make sure to checksum the final byte
    if i != skipword && len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    sum
}

// Returns in big endian
pub fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !sum as u16
}

