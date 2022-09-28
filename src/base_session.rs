use std::io;
use std::io::Read;

pub struct BaseSession<T: io::Read + io::Write> {
    //io_device: T,
    read_buf: io::BufReader<T>,
    read_idx: usize,
    read_size: usize,
    write_idx: usize,
    write_size: usize,
}

impl<T: io::Read + io::Write> BaseSession<T> {
    pub fn new(io: T) -> Self {
        BaseSession {
            read_buf: io::BufReader::new(io),
            read_idx: 0,
            read_size: 0,
            write_idx: 0,
            write_size: 0,
        }
    }

    /// Reads data from the io device being wrapped by this session into a supplied packet.
    /// Validity checks are not performed here, but should instead be done after
    /// this function returns Ok(()). This function will only read as many bytes into the packet
    /// as are specified by the `packet_size` parameter
    ///
    /// If a nonblocking io device is passed in, this function may return an error
    /// of kind `WouldBlock`; in this case, the io device should be polled until
    /// it can be read again.
    pub fn read_packet(&mut self, packet: &mut [u8]) -> io::Result<()> {
        if self.read_size > 0 && packet.len() != self.read_size {
            // TODO: add more comprehensive error checking by saving a hash of the packet?
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected internal error occurred while reading a packet".to_string(),
            )); // TODO: make error message clearer
        }

        if self.read_size == 0 {
            self.read_size = packet.len();
        }

        let mut slice = &mut packet[self.read_idx..];

        while !slice.is_empty() {
            match self.read_buf.read(slice) {
                Ok(amount_read) => {
                    slice = &mut slice[amount_read..];
                    self.read_idx += amount_read;
                }
                Err(e) => {
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            }
        }

        // Reset state once packet fully read
        self.read_idx = 0;
        self.read_size = 0;

        Ok(())
    }

    /// Writes a single packet to the io device being wrapped by this session.
    /// Validity checks are not performed here, but should instead be done before
    /// passing any data to this function.
    ///
    /// If a nonblocking io device is passed in, this function may return an error
    /// of type `WouldBlock`; in this case, the io device should be polled until
    /// it can be read again.
    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let io = self.read_buf.get_mut();

        if self.write_size > 0 && packet.len() != self.write_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected internal error occurred while writing a packet".to_string(),
            )); // TODO: put better error string here
        }

        if self.write_size == 0 {
            self.write_size = packet.len();
        }

        let mut slice = &packet[self.write_idx..];

        while !slice.is_empty() {
            match io.write(slice) {
                Ok(amount_written) => {
                    slice = &slice[amount_written..]; // Guaranteed not to index out of bounds at runtime--Write API will never return written amount greater than buf passed in
                    self.write_idx += amount_written;
                }
                Err(e) => {
                    if e.kind() != io::ErrorKind::Interrupted {
                        return Err(e);
                    }
                }
            };
        }

        // Reset state once packet fully read
        self.write_idx = 0;
        self.write_size = 0;

        Ok(())
    }

    /// Gets a reference to the underlying io device.
    ///
    /// It is inadvisable to directly read from or write to the underlying io device;
    /// this should only be used to poll the io device for events.
    pub fn get_io_ref(&self) -> &T {
        &self.read_buf.get_ref()
    }
}
