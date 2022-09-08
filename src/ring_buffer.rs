use std::collections::VecDeque;
use super::wire::Buffer;
use std::io::{IoSlice, IoSliceMut};


const HIGH_BUFFER_CNT: usize = 200; // 50 MB
const BUFFER_SIZE: usize = 256*1024; // 256 KB (1/4 MB)




pub struct RingBuffer {
    buffers: VecDeque<[u8; BUFFER_SIZE]>,
    read_idx: usize,
    last_readable_buffer_idx: usize,
    last_readable_byte_idx: usize,
    write_buffer_idx: usize,
    write_byte_idx: usize,
}


impl Buffer for RingBuffer {

    fn new() -> Self {
        RingBuffer {
            buffers: VecDeque::new(),
            read_idx: 0,
            last_readable_buffer_idx: 0,
            last_readable_byte_idx: 0,
            write_buffer_idx: 0,
            write_byte_idx: 0,
        }
    }
    
    // TODO: use 'available' and 'filled' rather than 'readable' and 'writable'?

    fn get_writable_vectored<'a>(&'a mut self) -> &mut [IoSliceMut<'a>] {
        let mut slices = Vec::from_iter(self.buffers.iter_mut().enumerate().map(|(idx, buf)| {
            IoSliceMut::new(if self.buffers.len() == 1 {
                &mut buf[self.read_idx..self.last_readable_byte_idx]
            } else if idx == 0 {
                &mut buf[self.read_idx..]
            } else if idx + 1 == self.buffers.len() {
                &mut buf[..self.last_readable_byte_idx]
            } else {
                buf
            })
        }));

        slices.as_mut_slice()
    }

    fn advance_written(&mut self, num_bytes_written: usize) {
        while num_bytes_written > (BUFFER_SIZE - self.write_byte_idx) { // TODO: >= rather than >?
            num_bytes_written -= BUFFER_SIZE - self.write_byte_idx;
            self.write_byte_idx = 0;
            self.write_buffer_idx += 1;
        }

        self.write_byte_idx += num_bytes_written;

        assert!(self.write_buffer_idx < self.buffers.len());
    }

    fn advance_readable(&mut self, num_bytes_readable: usize) {
        while num_bytes_readable > (BUFFER_SIZE - self.last_readable_byte_idx) { // TODO: >= rather than >?
            num_bytes_readable -= BUFFER_SIZE - self.last_readable_byte_idx;
            self.last_readable_byte_idx = 0;
            self.last_readable_buffer_idx += 1;
        }

        self.last_readable_byte_idx += num_bytes_readable;

        assert!((self.last_readable_buffer_idx < self.write_buffer_idx) || (self.last_readable_buffer_idx == self.write_buffer_idx && self.last_readable_byte_idx <= self.write_byte_idx));
    }

    fn get_readable_vectored<'a>(&'a self) -> &[IoSlice<'a>] {
        let slices = Vec::from_iter(self.buffers.iter().enumerate().map(|(idx, buf)| {
            IoSlice::new(if self.buffers.len() == 1 {
                &buf[self.read_idx..self.last_readable_byte_idx]
            } else if idx == 0 {
                &buf[self.read_idx..]
            } else if idx + 1 == self.buffers.len() {
                &buf[..self.last_readable_byte_idx]
            } else {
                buf
            })
        }));

        slices.as_slice()
    }

    fn advance_read(&mut self, num_bytes_read: usize) {
        while num_bytes_read > (BUFFER_SIZE - self.read_idx) { // TODO: >= rather than >?
            num_bytes_read -= BUFFER_SIZE - self.read_idx;
            self.read_idx = 0;

            if self.buffers.len() <= HIGH_BUFFER_CNT {
                self.buffers.push_back(self.buffers[0])
            }

            self.buffers.pop_front();

            assert!(self.last_readable_buffer_idx > 0 && self.write_buffer_idx > 0);
            self.last_readable_buffer_idx -= 1;
            self.write_buffer_idx -= 1;
        }

        self.read_idx += num_bytes_read;

        assert!(self.read_idx <= self.last_readable_byte_idx);
    }

    /// Expands the writable capacity of the buffer by at least `num_bytes` bytes.
    /// Note that this function may expand the capacity of the buffer by an arbitrarily 
    /// greater amount than `num_bytes`.
    fn expand(&mut self, num_bytes: usize) {
        let num_buffers = (num_bytes / BUFFER_SIZE) + if (num_bytes % BUFFER_SIZE) == 0 { 0 } else { 1 };
        
        for _ in 0..num_buffers {
            self.buffers.push_back([0; BUFFER_SIZE]);
        }
    }
}

