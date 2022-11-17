
use std::{collections::HashMap, mem::size_of};



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

/*
pub trait Readable {
    fn read<'a>(reader: WireReader<'a>) -> Result<Self, &'static str>;

    fn read_exact<'a, const S: usize>(reader: WireReader<'a>) -> Self;
}

impl Readable for u32 {
    fn read<'a>(reader: WireReader<'a>) -> Result<Self, &'static str> {
        let (int_bytes, remaining_bytes) = try_split_at(reader.bytes, size_of::<T>());

        let res: Result<T::Bytes, _> = std::convert::TryInto::try_into(int_bytes);
        match res {
            Ok(b) => {
                self.bytes = remaining_bytes;
                Ok(T::from_be(b)) // Network Byte order is big-endian
            }
            Err(_) => Err(INSUFFICIENT_DATA_ERROR),
        }

        1
    }

    fn read_exact<'a, const S: usize>(reader: WireReader<'a>) -> Self {

    }
}
*/


pub trait EndianConvert<'a>: Sized + PartialOrd  + TryInto<usize> {
    type Bytes: TryFrom<&'a [u8]>;

    fn from_be(bytes: Self::Bytes) -> Self;

    fn from_le(bytes: Self::Bytes) -> Self;

    fn zero() -> Self;
}

macro_rules! derive_endian{
    ($int:ty)=> {
impl<'a> EndianConvert<'a> for $int {
    type Bytes = &'a[u8; size_of::<$int>()];

    fn from_be(bytes: Self::Bytes) -> Self {
        <$int>::from_be_bytes(*bytes)
    }

    fn from_le(bytes: Self::Bytes) -> Self {
        <$int>::from_be_bytes(*bytes)
    }

    fn zero() -> Self {
        0
    }
}
    }
}

derive_endian!(i8);
derive_endian!(u8);
derive_endian!(i16);
derive_endian!(u16);
derive_endian!(i32);
derive_endian!(u32);
derive_endian!(i64);
derive_endian!(u64);
derive_endian!(i128);
derive_endian!(u128);
derive_endian!(usize);

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

    /*
    pub fn read_byte(&mut self) -> Result<u8, &'static str> {
        match self.bytes.split_first() {
            Some((byte, remaining_bytes)) => {
                self.bytes = remaining_bytes;
                Ok(*byte)
            }
            None => Err(INSUFFICIENT_DATA_ERROR),
        }
    }
    */

    pub fn read_fixed_str(&mut self, str_len: usize) -> Result<&'a str, &'static str> {
        let (string, remaining_bytes) = try_split_at(self.bytes, str_len);
        if string.len() < str_len {
            return Err(INSUFFICIENT_DATA_ERROR)
        }

        self.bytes = remaining_bytes;
        return std::str::from_utf8(string).or_else(|_| Err(UTF8_ENCODING_ERROR));       
    }

    pub fn read_str(&mut self) -> Result<&'a str, &'static str> {
        let (string, remaining_bytes) = match try_split_once(self.bytes, 0) {
            Some(vals) => vals,
            None => return Err(MISSING_NULL_TERMINATOR_ERROR),
        };

        self.bytes = remaining_bytes;
        return std::str::from_utf8(string).or_else(|_| Err(UTF8_ENCODING_ERROR));
    }

    pub fn read_str_and_finalize(&mut self) -> Result<&'a str, &'static str> {
        let ret = self.read_str()?;
        self.finalize()?;
        Ok(ret)
    }

    pub fn read_strs(&mut self, count: usize) -> Result<Vec<&'a str>, &'static str> {
        let mut strings = Vec::new();
        for _ in 0..count {
            strings.push(self.read_str()?);
        }

        Ok(strings)
    }

    pub fn read_strs_and_finalize(
        &mut self,
        count: usize,
    ) -> Result<Vec<&'a str>, &'static str> {
        let ret = self.read_strs(count)?;
        self.finalize()?;
        Ok(ret)
    }

    pub fn read_strs_term(&mut self) -> Result<Vec<&'a str>, &'static str> {
        let mut strings = Vec::new();
        while !self.empty() && self.bytes.get(0) != Some(&0) {
            strings.push(self.read_str()?);
        }

        match self.bytes.split_first() {
            Some((0, remaining_bytes)) => self.bytes = remaining_bytes,
            _ => return Err(MISSING_NULL_TERMINATOR_ERROR),
        }

        Ok(strings)
    }

    pub fn read_strs_term_and_finalize(&mut self) -> Result<Vec<&'a str>, &'static str> {
        let ret = self.read_strs_term()?;
        self.finalize()?;
        Ok(ret)
    }

    pub fn read_str_str_map_sized(
        &mut self,
        num_entries: usize,
    ) -> Result<HashMap<&'a str, &'a str>, &'static str> {
        let mut map = HashMap::new();
        for _ in 0..num_entries {
            let key = self.read_str()?;
            let value = self.read_str()?;
            if map.insert(key, value) != None {
                return Err(UNIQUE_KEY_ERROR);
            }
        }

        Ok(map)       
    }

    pub fn read_str_str_map_term(
        &mut self,
    ) -> Result<HashMap<&'a str, &'a str>, &'static str> {
        let mut map = HashMap::new();
        while !self.empty() && self.bytes.get(0) != Some(&0) {
            let key = self.read_str()?;
            let value = self.read_str()?;
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

    pub fn read_u8_str_map_term(&mut self) -> Result<HashMap<u8, &'a str>, &'static str> {
        let mut map = HashMap::new();
        while !self.empty() && self.bytes.get(0) != Some(&0) {
            let key = self.read()?;
            let value = self.read_str()?;
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

    pub fn read_u8_str_map_term_and_finalize(
        &mut self,
    ) -> Result<HashMap<u8, &'a str>, &'static str> {
        let ret = self.read_u8_str_map_term()?;
        self.finalize()?;
        Ok(ret)
    }

    pub fn read_u32_3byte(&mut self) -> Result<u32, &'static str> {
        let (int32_bytes, remaining_bytes) = try_split_at(self.bytes, 3);
        let mut buffer = [0u8; 4];

        match int32_bytes.get(..3) {
            Some(b) => {
                buffer[..3].copy_from_slice(b);
                self.bytes = remaining_bytes;
                Ok(u32::from_be_bytes(buffer)) // Network Byte order is big-endian
            }
            None => Err(INSUFFICIENT_DATA_ERROR),
        }
    }

    pub fn read_u32_3byte_and_finalize(&mut self) -> Result<u32, &'static str> {
        let ret = self.read_u32_3byte()?;
        self.finalize()?;
        Ok(ret)
    }

    /*
    pub fn read_integral<T, const L: usize>(&mut self) -> Result<T, &'static str> 
    where T: EndianConvert<'a> {
        if L > size_of::<T>() {
            return Err("internal error: read_integral function misused")
        }

        let (partial_bytes, remaining_bytes) = try_split_at(self.bytes, L);
        let mut all_bytes: Vec<u8> = partial_bytes.into();
        all_bytes.extend(std::iter::repeat(0).take(size_of::<T>() - L));

        let s = all_bytes.as_slice();

        let res: Result<T::Bytes, _> = std::convert::TryInto::try_into(s);
        let fin = match res {
            Ok(b) => {
                self.bytes = remaining_bytes;
                T::from_be(b) // Network Byte order is big-endian
            }
            Err(_) => return Err(INSUFFICIENT_DATA_ERROR),
        };

        drop(all_bytes.clone());

        Ok(fin)
    }
    */

    pub fn read<T>(&mut self) -> Result<T, &'static str> 
    where T: EndianConvert<'a> {
        let (int_bytes, remaining_bytes) = try_split_at(self.bytes, size_of::<T>());

        let res: Result<T::Bytes, _> = std::convert::TryInto::try_into(int_bytes);
        match res {
            Ok(b) => {
                self.bytes = remaining_bytes;
                Ok(T::from_be(b)) // Network Byte order is big-endian
            }
            Err(_) => Err(INSUFFICIENT_DATA_ERROR),
        }
    }

    pub fn read_and_finalize<T>(&mut self) -> Result<T, &'static str> 
    where T: EndianConvert<'a> {
        let ret = self.read()?;
        self.finalize()?;
        Ok(ret)
    }

    
    pub fn read_length<T>(&mut self) -> Result<usize, &'static str>
    where T: EndianConvert<'a>  {
        let len: T = self.read()?;
        match len.try_into() { // TODO: make sure this fails on negative
            Ok(l) => Ok(l),
            _ => Err(NEGATIVE_LENGTH_ERROR)
        }
    }
 
    pub fn read_length_and_finalize<T>(&mut self) -> Result<usize, &'static str> 
    where T: EndianConvert<'a> {
        let ret = self.read_length::<T>()?;
        self.finalize()?;
        Ok(ret)
    }

    pub fn read_list<T>(&mut self, length: usize) -> Result<Vec<T>, &'static str> 
    where T: EndianConvert<'a> {
        let mut list = Vec::new();
        for _ in 0..length {
            list.push(self.read()?);
        }
        Ok(list)
    }

    pub fn read_list_and_finalize<T>(&mut self, length: usize) -> Result<Vec<T>, &'static str> 
    where T: EndianConvert<'a> {
        let ret = self.read_list(length)?;
        self.finalize()?;
        Ok(ret)
    }

    pub fn read_nullable_int32_length(&mut self) -> Result<Option<usize>, &'static str> {
        let i: i32 = self.read()?;
        match i.try_into() {
            Ok(val) => Ok(Some(val)),
            Err(_) if i == -1 => Ok(None),
            _ => Err(NEGATIVE_LENGTH_ERROR),
        }
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
        let ret = self.read_bytes(count)?;
        self.finalize()?;
        Ok(ret)
    }

    pub fn read_bytes_term(&mut self) -> Result<&'a [u8], &'static str> {
        let (needed_bytes, remaining_bytes) = match try_split_once(self.bytes, 0) {
            Some(res) => res,
            None => return Err(MISSING_NULL_TERMINATOR_ERROR)
        };

        self.bytes = remaining_bytes;
        Ok(needed_bytes)
    }

    pub fn read_bytes_term_and_finalize(&mut self) -> Result<&'a [u8], &'static str> {
        let ret = self.read_bytes_term()?;
        self.finalize()?;
        Ok(ret)
    }


    pub fn read_remaining_bytes(&mut self) -> &'a [u8] {
        let remaining = self.bytes;
        self.bytes = &[];
        remaining
    }

    pub fn read_bytearray<const T: usize>(&mut self) -> Result<&'a [u8; T], &'static str> {
        let (needed_bytes, remaining_bytes) = try_split_at(self.bytes, T);
        match needed_bytes.try_into() {
            Ok(exact) => {
                self.bytes = remaining_bytes;
                Ok(exact)
            },
            _ => Err(INSUFFICIENT_DATA_ERROR)
        }
    }

    pub fn read_bytearray_and_finalize<const T: usize>(&mut self) -> Result<&'a [u8; T], &'static str> {
        let ret = self.read_bytearray()?;
        self.finalize()?;
        Ok(ret)
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

/*
fn split_at<T, const S: usize>(buffer: &[T; S], index: usize) -> Result<(&[T; S], &[T]), &'static str> {
    
    (
        buffer.get(..index).unwrap_or(buffer),
        buffer.get(index..).unwrap_or(&[]),
    )
}
*/

/// Splits the slice into two slices at the first instance of `value`, or returns `None` if `value` is not in the slice.
fn try_split_once<T: Eq>(buffer: &[T], value: T) -> Option<(&[T], &[T])> {
    match buffer.split(|t| *t == value).next() {
        Some(split_buf) => Some((split_buf, buffer.get(split_buf.len() + 1..).unwrap_or(&[]))),
        None => None,
    }
}
