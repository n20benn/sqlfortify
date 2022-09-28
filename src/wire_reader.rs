use std::collections::HashMap;

const INSUFFICIENT_DATA_ERROR: &'static str =
    "insufficient data in wire packet to parse a required field";
const OVERSIZED_PACKET_ERROR: &'static str =
    "invalid packet length--unrecognized data at end of packet";
const MISSING_NULL_TERMINATOR_ERROR: &'static str =
    "null terminator missing for a required field in the wire packet";
const UTF8_ENCODING_ERROR: &'static str = "invalid UTF-8 characters detected in field";
const UNIQUE_KEY_ERROR: &'static str = "duplicate value found in field that requires unique values";
const NEGATIVE_LENGTH_ERROR: &'static str =
    "wire packet contained length field with invalid negative value";

pub struct WireReader<'a> {
    bytes: &'a [u8],
}

impl<'a> WireReader<'a> {
    pub fn new(wire: &'a [u8]) -> Self {
        WireReader { bytes: wire }
    }

    pub fn empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn read_byte(&mut self) -> Result<u8, &'static str> {
        match self.bytes.split_first() {
            Some((byte, remaining_bytes)) => {
                self.bytes = remaining_bytes;
                Ok(*byte)
            }
            None => Err(INSUFFICIENT_DATA_ERROR),
        }
    }

    pub fn read_utf8_c_str(&mut self) -> Result<&'a str, &'static str> {
        let (string, remaining_bytes) = match try_split_once(self.bytes, 0) {
            Some(vals) => vals,
            None => return Err(MISSING_NULL_TERMINATOR_ERROR),
        };

        self.bytes = remaining_bytes;
        return std::str::from_utf8(string).or_else(|_| Err(UTF8_ENCODING_ERROR));
    }

    pub fn read_utf8_c_str_and_finalize(&mut self) -> Result<&'a str, &'static str> {
        let ret = self.read_utf8_c_str();
        self.finalize()?;
        return ret;
    }

    pub fn read_utf8_c_strs(&mut self, count: usize) -> Result<Vec<&'a str>, &'static str> {
        let mut strings = Vec::new();
        for _ in 0..count {
            strings.push(self.read_utf8_c_str()?);
        }

        Ok(strings)
    }

    pub fn read_utf8_c_strs_and_finalize(
        &mut self,
        count: usize,
    ) -> Result<Vec<&'a str>, &'static str> {
        let ret = self.read_utf8_c_strs(count);
        self.finalize()?;
        return ret;
    }

    pub fn read_utf8_c_strs_term(&mut self) -> Result<Vec<&'a str>, &'static str> {
        let mut strings = Vec::new();
        while !self.empty() && self.bytes.get(0) != Some(&0) {
            strings.push(self.read_utf8_c_str()?);
        }

        match self.bytes.split_first() {
            Some((0, remaining_bytes)) => self.bytes = remaining_bytes,
            _ => return Err(MISSING_NULL_TERMINATOR_ERROR),
        }

        Ok(strings)
    }

    pub fn read_term_utf8_c_strs_and_finalize(&mut self) -> Result<Vec<&'a str>, &'static str> {
        let ret = self.read_utf8_c_strs_term();
        self.finalize()?;
        return ret;
    }

    pub fn read_utf8_string_string_map(
        &mut self,
    ) -> Result<HashMap<&'a str, &'a str>, &'static str> {
        let mut map = HashMap::new();
        while !self.empty() && self.bytes.get(0) != Some(&0) {
            let key = self.read_utf8_c_str()?;
            let value = self.read_utf8_c_str()?;
            if map.insert(key, value) != None {
                return Err(UNIQUE_KEY_ERROR);
            }
        }

        match self.bytes.split_first() {
            Some((0, remaining_bytes)) => self.bytes = remaining_bytes,
            _ => return Err(MISSING_NULL_TERMINATOR_ERROR),
        }

        Ok(map)
    }

    pub fn read_term_utf8_byte_string_map(&mut self) -> Result<HashMap<u8, &'a str>, &'static str> {
        let mut map = HashMap::new();
        while !self.empty() && self.bytes.get(0) != Some(&0) {
            let key = self.read_byte()?;
            let value = self.read_utf8_c_str()?;
            if map.insert(key, value) != None {
                return Err(UNIQUE_KEY_ERROR);
            }
        }

        match self.bytes.split_first() {
            Some((0, remaining_bytes)) => self.bytes = remaining_bytes,
            _ => return Err(MISSING_NULL_TERMINATOR_ERROR),
        }

        Ok(map)
    }

    pub fn read_term_utf8_byte_string_map_and_finalize(
        &mut self,
    ) -> Result<HashMap<u8, &'a str>, &'static str> {
        let ret = self.read_term_utf8_byte_string_map();
        self.finalize()?;
        return ret;
    }

    pub fn read_int32(&mut self) -> Result<i32, &'static str> {
        let (int32_bytes, remaining_bytes) = try_split_at(self.bytes, 4);
        let res: Result<&[u8; 4], _> = int32_bytes.try_into();
        match res {
            Ok(b) => {
                self.bytes = remaining_bytes;
                Ok(i32::from_be_bytes(*b)) // Network Byte order is big-endian
            }
            Err(_) => Err(INSUFFICIENT_DATA_ERROR),
        }
    }

    pub fn read_int32_and_finalize(&mut self) -> Result<i32, &'static str> {
        let ret = self.read_int32();
        self.finalize()?;
        return ret;
    }

    pub fn read_int16(&mut self) -> Result<i16, &'static str> {
        let (int16_bytes, remaining_bytes) = try_split_at(self.bytes, 2);
        let res: Result<&[u8; 2], _> = int16_bytes.try_into();
        match res {
            Ok(b) => {
                self.bytes = remaining_bytes;
                Ok(i16::from_be_bytes(*b)) // Network Byte order is big-endian
            }
            Err(_) => Err(INSUFFICIENT_DATA_ERROR),
        }
    }

    pub fn read_int16_and_finalize(&mut self) -> Result<i16, &'static str> {
        let ret = self.read_int16();
        self.finalize()?;
        return ret;
    }

    pub fn read_int32_length(&mut self) -> Result<usize, &'static str> {
        self.read_int32()?.try_into().or(Err(NEGATIVE_LENGTH_ERROR))
    }

    pub fn read_int16_length(&mut self) -> Result<usize, &'static str> {
        self.read_int16()?.try_into().or(Err(NEGATIVE_LENGTH_ERROR))
    }

    pub fn read_nullable_int32_length(&mut self) -> Result<Option<usize>, &'static str> {
        let int32 = self.read_int32()?;
        match int32.try_into() {
            Ok(val) => Ok(Some(val)),
            Err(_) if int32 == -1 => Ok(None),
            _ => Err(NEGATIVE_LENGTH_ERROR),
        }
    }

    pub fn read_int32_list(&mut self, length: usize) -> Result<Vec<i32>, &'static str> {
        let mut list = Vec::new();
        for _ in 0..length {
            list.push(self.read_int32()?);
        }
        Ok(list)
    }

    pub fn read_int32_list_and_finalize(
        &mut self,
        length: usize,
    ) -> Result<Vec<i32>, &'static str> {
        let ret = self.read_int32_list(length);
        self.finalize()?;
        return ret;
    }

    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], &'static str> {
        let (needed_bytes, remaining_bytes) = try_split_at(self.bytes, count);
        if needed_bytes.len() == count {
            self.bytes = remaining_bytes;
            Ok(needed_bytes)
        } else {
            Err(INSUFFICIENT_DATA_ERROR)
        }
    }

    pub fn read_bytes_and_finalize(&mut self, count: usize) -> Result<&'a [u8], &'static str> {
        let ret = self.read_bytes(count);
        self.finalize()?;
        return ret;
    }

    pub fn read_remaining_bytes(&mut self) -> &'a [u8] {
        let remaining = self.bytes;
        self.bytes = &[];
        remaining
    }

    pub fn read_4_bytes(&mut self) -> Result<&'a [u8; 4], &'static str> {
        let (needed_bytes, remaining_bytes) = try_split_at(self.bytes, 4);
        match needed_bytes.try_into() {
            Ok(exact) => {
                self.bytes = remaining_bytes;
                Ok(exact)
            }
            Err(_) => Err(INSUFFICIENT_DATA_ERROR),
        }
    }

    pub fn read_4_bytes_and_finalize(&mut self) -> Result<&'a [u8; 4], &'static str> {
        let ret = self.read_4_bytes();
        self.finalize()?;
        return ret;
    }

    /// Advances the reader's index by up to `num_bytes` forward. If the reader's index
    /// reaches the end in fewer than `num_bytes`, it will stay at the end.
    pub fn advance_up_to(&mut self, num_bytes: usize) {
        self.bytes = self.bytes.get(num_bytes..).unwrap_or(&[])
    }

    pub fn finalize(&mut self) -> Result<(), &'static str> {
        if self.bytes.len() > 0 {
            self.bytes = &[];
            Err(OVERSIZED_PACKET_ERROR)
        } else {
            Ok(())
        }
    }
}

/// Splits the slice into two slices, the second of which beginning at `index`. If `index` is greater
/// or equal to the the length of `buffer`, the second slice will be empty and the first slice will be
/// the contents of `buffer`.
fn try_split_at<T>(buffer: &[T], index: usize) -> (&[T], &[T]) {
    (
        buffer.get(..index).unwrap_or(buffer),
        buffer.get(index..).unwrap_or(&[]),
    )
}

/// Splits the slice into two slices at the first instance of `value`, or returns `None` if `value` is not in the slice.
fn try_split_once<T: Eq>(buffer: &[T], value: T) -> Option<(&[T], &[T])> {
    match buffer.split(|t| *t == value).next() {
        Some(split_buf) => Some((split_buf, buffer.get(split_buf.len() + 1..).unwrap_or(&[]))),
        None => None,
    }
}
