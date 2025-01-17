
use crate::socket::{IpSocket, BlockingIpSocket, NonBlockingIpSocket, FragmentConfig};

use std::ffi::c_int;
use std::net::IpAddr;


pub const IPPROTO_ETHERIP: c_int = 97;

pub const ETHERNET_MIN_MTU: usize = 64;
pub const ETHERNET_MAX_MTU: usize = 9216;

pub const ETHERNET_HEADER_SIZE: usize = 14;
pub const ETHERNET_CRC_SIZE: usize = 4;

pub const ETHERNET_MIN_FRAME_SIZE: usize = ETHERNET_MIN_MTU + ETHERNET_HEADER_SIZE + ETHERNET_CRC_SIZE;
pub const ETHERNET_MAX_FRAME_SIZE: usize = ETHERNET_MAX_MTU + ETHERNET_HEADER_SIZE + ETHERNET_CRC_SIZE;

pub const ETHERIP_HEADER_SIZE: usize = 2;

pub const ETHERIP_MIN_DATAGRAM_SIZE: usize = ETHERNET_MIN_FRAME_SIZE + ETHERIP_HEADER_SIZE;
pub const ETHERIP_MAX_DATAGRAM_SIZE: usize = ETHERNET_MAX_FRAME_SIZE + ETHERIP_HEADER_SIZE;

/// EtherIP datagram parser
#[derive(Debug, Clone, Copy)]
pub struct EtherIpParser<const N: usize> {
    datagram_length: usize, // Ethernet frame length + 2
    data: [u8; N], // EtherIP datagram
}

impl<const N: usize> EtherIpParser<N> {
    /// Create a new EtherIP parser without initializing the buffer
    #[inline]
    #[allow(invalid_value)]
    pub unsafe fn new() -> Self {
        assert!(N >= ETHERIP_MIN_DATAGRAM_SIZE);

        unsafe { std::mem::MaybeUninit::uninit().assume_init() }
    }

    /// Create a new EtherIP parser with a zeroed buffer
    #[inline]
    pub fn new_zeroed() -> Self {
        assert!(N >= ETHERIP_MIN_DATAGRAM_SIZE);

        Self {
            datagram_length: 0,
            data: [0; N],
        }
    }

    /// Get a writable reference to the EtherIP buffer
    #[inline]
    pub fn etherip_mut(&mut self) -> (&mut usize, &mut [u8]) {
        (&mut self.datagram_length, &mut self.data)
    }

    /// Get a reference to the Ethernet buffer
    #[inline]
    pub fn parse_ethernet(&self) -> Option<&[u8]> {
        if self.data[0] != 0b0011_0000 || self.data[1] != 0b0000_0000 {
            return None;
        }
        let len = self.datagram_length;
        if len <= N && len >= ETHERIP_MAX_DATAGRAM_SIZE {
            Some(&self.data[2..len])
        } else {
            None
        }
    }
}

/// EtherIP datagram builder
#[derive(Debug, Clone, Copy)]
pub struct EtherIpBuilder<const N: usize> {
    ether_frame_length: usize, // EtherIP datagram length - 2
    data: [u8; N], // EtherIP datagram
}

impl<const N: usize> EtherIpBuilder<N> {
    /// Create a new EtherIP builder
    #[inline]
    #[allow(invalid_value)]
    pub unsafe fn new() -> Self {
        assert!(N >= ETHERIP_MIN_DATAGRAM_SIZE);

        let mut builder: Self = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        builder.data[0] = 0b0011_0000;
        builder.data[1] = 0b0000_0000;
        builder
    }

    /// Create a new EtherIP builder with a zeroed buffer
    #[inline]
    pub fn new_zeroed() -> Self {
        assert!(N >= ETHERIP_MIN_DATAGRAM_SIZE);

        let mut builder = Self {
            ether_frame_length: 0,
            data: [0; N],
        };
        builder.data[0] = 0b0011_0000;
        builder.data[1] = 0b0000_0000;
        builder
    }

    /// Get a writable reference to the Ethernet buffer
    #[inline]
    pub fn ethernet_mut(&mut self) -> (&mut usize, &mut [u8]) {
        (&mut self.ether_frame_length, &mut self.data[2..])
    }

    /// Get a reference to the EtherIP buffer
    #[inline]
    pub fn build_etherip(&self) -> Option<&[u8]> {
        let len = self.ether_frame_length + 2;
        if len <= N && len >= ETHERIP_MIN_DATAGRAM_SIZE {
            Some(&self.data[..len])
        } else {
            None
        }
    }
}

pub type DefaultParser = EtherIpParser<ETHERIP_MAX_DATAGRAM_SIZE>;
pub type DefaultBuilder = EtherIpBuilder<ETHERIP_MAX_DATAGRAM_SIZE>;

/// EtherIP socket
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct EtherIpSocket {
    socket: NonBlockingIpSocket<IPPROTO_ETHERIP>,
}

impl EtherIpSocket {
    /// Create a new EtherIP socket
    pub fn new() -> std::io::Result<Self> {
        let socket = NonBlockingIpSocket::new()?;
        socket.set_fragment_config(&FragmentConfig::Fragment)?;
        Ok(Self { socket })
    }

    /// Bind the socket to a local address
    pub fn bind(&self, addr: IpAddr) -> std::io::Result<()> {
        self.socket.bind(addr)
    }

    /// Bind the socket to an unspecified address
    pub fn bind_unspecified(&self) -> std::io::Result<()> {
        self.socket.bind_unspecified()
    }

    /// Bind the socket to a device
    pub fn bind_device(&self, device: Option<&[u8]>) -> std::io::Result<()> {
        self.socket.bind_device(device)
    }

    /// Send a datagram to a remote address
    #[inline]
    pub async fn send_to<const N: usize>(&self, datagram: &EtherIpBuilder<N>, addr: IpAddr) -> std::io::Result<usize> {
        match datagram.build_etherip() {
            Some(data) => self.socket.send_to(data, addr).await,
            None => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid EtherIP datagram")),
        }
    }

    /// Receive a datagram from a remote address
    #[inline]
    pub async fn recv_from<const N: usize>(&self, datagram: &mut EtherIpParser<N>) -> std::io::Result<IpAddr> {
        let (len, addr) = self.socket.recv_from(&mut datagram.data).await?;
        datagram.datagram_length = len;
        Ok(addr)
    }
}

/// Blocking EtherIP socket
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct BlockingEtherIpSocket {
    socket: BlockingIpSocket<IPPROTO_ETHERIP>,
}

impl BlockingEtherIpSocket {
    /// Create a new EtherIP socket
    pub fn new() -> std::io::Result<Self> {
        let socket = BlockingIpSocket::new()?;
        socket.set_fragment_config(&FragmentConfig::Fragment)?;
        Ok(Self { socket })
    }

    /// Bind the socket to a local address
    pub fn bind(&self, addr: IpAddr) -> std::io::Result<()> {
        self.socket.bind(addr)
    }

    /// Bind the socket to an unspecified address
    pub fn bind_unspecified(&self) -> std::io::Result<()> {
        self.socket.bind_unspecified()
    }

    /// Bind the socket to a device
    pub fn bind_device(&self, device: Option<&[u8]>) -> std::io::Result<()> {
        self.socket.bind_device(device)
    }

    /// Send a datagram to a remote address
    #[inline]
    pub fn send_to<const N: usize>(&self, datagram: &EtherIpBuilder<N>, addr: IpAddr) -> std::io::Result<usize> {
        match datagram.build_etherip() {
            Some(data) => self.socket.send_to(data, addr),
            None => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid EtherIP datagram")),
        }
    }

    /// Receive a datagram from a remote address
    #[inline]
    pub fn recv_from<const N: usize>(&self, datagram: &mut EtherIpParser<N>) -> std::io::Result<IpAddr> {
        let (len, addr) = self.socket.recv_from(&mut datagram.data)?;
        datagram.datagram_length = len;
        Ok(addr)
    }
}
