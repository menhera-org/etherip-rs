// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=&2 sw=2 et ai :

pub use parking_lot;
pub use anyhow;
pub use tokio;
pub use log;
pub use clap;
pub use syslog;
pub use serde;
pub use toml;
pub use libc;
pub use futures;
pub use crossbeam_channel;
pub use nix;

pub mod config;
pub mod tap;

use std::io::{Error, ErrorKind};
use std::os::fd::AsRawFd;

use std::net::{IpAddr, Ipv6Addr};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

pub const PROTO_ETHERIP: libc::c_int = 97;


/// Convert an `Ipv6Addr` to an `IpAddr` by mapping IPv4 addresses to IPv6.
pub fn to_ipv6_addr(addr: IpAddr) -> Ipv6Addr {
  match addr {
    IpAddr::V4(v4_addr) => v4_addr.to_ipv6_mapped(),
    IpAddr::V6(v6_addr) => v6_addr,
  }
}

/// Convert an `IpAddr` to an `Ipv6Addr` by unmapping IPv4 addresses from IPv6.
pub fn from_ipv6_addr(v6_addr: Ipv6Addr) -> IpAddr {
  match v6_addr.to_ipv4_mapped() {
    Some(v4_addr) => IpAddr::V4(v4_addr),
    None => IpAddr::V6(v6_addr),
  }
}

#[derive(Debug)]
pub struct RawIpSocket {
  socket_fd: libc::c_int,
}

/// Configuration for Path MTU Discovery (PMTUD) for an `IpSocket`.
#[derive(Debug, Clone, Copy)]
pub enum FragmentConfig {
  /// Fragment large packets.
  Fragment,
  /// Reject large packets with EMSGSIZE.
  NoFragment,
}

impl RawIpSocket {
  fn new_raw(proto: libc::c_int) -> std::io::Result<Self> {
    let socket_fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW | libc::SOCK_NONBLOCK, proto) };
    if socket_fd < 0 {
      return Err(Error::last_os_error());
    }
    Ok(Self {
      socket_fd,
    })
  }

  fn set_mtu_discovery(&self, fragment_config: &FragmentConfig) -> std::io::Result<()> {
    let option = match fragment_config {
      FragmentConfig::Fragment => libc::IPV6_PMTUDISC_OMIT,
      FragmentConfig::NoFragment => libc::IPV6_PMTUDISC_DO,
    };
    let value = &option as *const libc::c_int as *const libc::c_void;
    let len = std::mem::size_of_val(&option) as u32;

    unsafe {
      if libc::setsockopt(self.socket_fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, value, len) < 0 {
        return Err(Error::last_os_error());
      }
      Ok(())
    }
  }

  fn bind_unspecified(&self) -> std::io::Result<()> {
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    addr.sin6_family = libc::AF_INET6 as u16;
    addr.sin6_port = 0;
    addr.sin6_flowinfo = 0;
    addr.sin6_addr = libc::in6_addr {
      s6_addr: [0; 16],
    };
    addr.sin6_scope_id = 0;

    let addr_len = std::mem::size_of_val(&addr) as u32;
    unsafe {
      if libc::bind(self.socket_fd, &addr as *const libc::sockaddr_in6 as *const libc::sockaddr, addr_len) < 0 {
        return Err(Error::last_os_error());
      }
      Ok(())
    }
  }

  pub fn new(proto: libc::c_int) -> std::io::Result<Self> {
    let socket = Self::new_raw(proto)?;
    socket.set_mtu_discovery(&FragmentConfig::Fragment)?;
    socket.bind_unspecified()?;
    Ok(socket)
  }

  pub fn new_with_fragment_config(proto: libc::c_int, fragment_config: FragmentConfig) -> std::io::Result<Self> {
    let socket = Self::new_raw(proto)?;
    socket.set_mtu_discovery(&fragment_config)?;
    socket.bind_unspecified()?;
    Ok(socket)
  }

  fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, libc::sockaddr_in6)> {
    let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let addr_len = std::mem::size_of_val(&addr) as u32;
    let n = unsafe {
      libc::recvfrom(
        self.socket_fd,
        buf.as_mut_ptr() as *mut libc::c_void,
        buf.len(),
        0,
        &mut addr as *mut libc::sockaddr_in6 as *mut libc::sockaddr,
        &addr_len as *const u32 as *mut u32
      )
    };
    if n < 0 {
      return Err(Error::last_os_error());
    }
    Ok((n as usize, addr))
  }

  fn send_to(&self, buf: &[u8], addr: &libc::sockaddr_in6) -> std::io::Result<usize> {
    let n = unsafe {
      libc::sendto(
        self.socket_fd,
        buf.as_ptr() as *const libc::c_void,
        buf.len(),
        0,
        addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
        std::mem::size_of_val(addr) as u32
      )
    };
    if n < 0 {
      return Err(Error::last_os_error());
    }
    Ok(n as usize)
  }
}

impl AsRawFd for RawIpSocket {
  fn as_raw_fd(&self) -> libc::c_int {
    self.socket_fd
  }
}

impl Drop for RawIpSocket {
  fn drop(&mut self) {
    unsafe {
      libc::close(self.socket_fd);
    }
  }
}

pub trait IpProtocol {
  fn protocol_number(&self) -> libc::c_int;
}

impl IpProtocol for libc::c_int {
  fn protocol_number(&self) -> libc::c_int {
    *self
  }
}

impl IpProtocol for libc::c_uint {
  fn protocol_number(&self) -> libc::c_int {
    *self as libc::c_int
  }
}

/// Raw IPv4/IPv6 dualstack socket backed by AF_INET6.
/// Large packets are fragmented by the kernel by default.
/// There is no need to `split` the `IpSocket` into a reader and a writer,
/// because it does not need to borrow self mutably to call `recv_from` and `send_to`.
/// Just wrap it in `Arc` and clone it.
#[derive(Debug)]
pub struct IpSocket<P>
where
  P: IpProtocol,
{
  inner: AsyncFd<RawIpSocket>,
  protocol: P,
}

impl<P> IpSocket<P>
where
  P: IpProtocol,
{
  pub fn new(protocol: P) -> std::io::Result<Self> {
    let socket = RawIpSocket::new(protocol.protocol_number())?;
    Ok(Self {
      inner: AsyncFd::with_interest(socket, Interest::READABLE | Interest::WRITABLE)?,
      protocol,
    })
  }

  pub fn new_with_fragment_config(protocol: P, fragment_config: FragmentConfig) -> std::io::Result<Self> {
    let socket = RawIpSocket::new_with_fragment_config(protocol.protocol_number(), fragment_config)?;
    Ok(Self {
      inner: AsyncFd::with_interest(socket, Interest::READABLE | Interest::WRITABLE)?,
      protocol,
    })
  }

  pub fn protocol(&self) -> libc::c_int {
    self.protocol.protocol_number()
  }

  async fn recv_from_raw(&self, buf: &mut [u8]) -> std::io::Result<(usize, libc::sockaddr_in6)> {
    loop {
      let mut guard = self.inner.readable().await?;
      match guard.try_io(|inner| inner.get_ref().recv_from(buf)) {
        Ok(result) => return result,
        Err(_would_block) => continue,
      }
    }
  }

  pub async fn recv_from_ipv6(&self, buf: &mut [u8]) -> std::io::Result<(usize, Ipv6Addr)> {
    let (n, addr) = self.recv_from_raw(buf).await?;
    Ok((n, addr.sin6_addr.s6_addr.into()))
  }

  pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, IpAddr)> {
    let (n, addr) = self.recv_from_ipv6(buf).await?;
    Ok((n, from_ipv6_addr(addr)))
  }

  async fn send_to_raw(&self, buf: &[u8], addr: &libc::sockaddr_in6) -> std::io::Result<usize> {
    loop {
      let mut guard = self.inner.writable().await?;
      match guard.try_io(|inner| inner.get_ref().send_to(buf, addr)) {
        Ok(result) => return result,
        Err(_would_block) => continue,
      }
    }
  }

  pub async fn send_to_ipv6(&self, buf: &[u8], addr: &Ipv6Addr) -> std::io::Result<usize> {
    let in6_addr = libc::in6_addr {
      s6_addr: addr.octets(),
    };
    let addr = libc::sockaddr_in6 {
      sin6_family: libc::AF_INET6 as u16,
      sin6_port: 0,
      sin6_flowinfo: 0,
      sin6_addr: in6_addr,
      sin6_scope_id: 0,
    };
    self.send_to_raw(buf, &addr).await
  }

  pub async fn send_to(&self, buf: &[u8], addr: &IpAddr) -> std::io::Result<usize> {
    self.send_to_ipv6(buf, &to_ipv6_addr(*addr)).await
  }
}

/// EtherIP protocol
#[derive(Debug)]
pub struct EtherIp ();

impl IpProtocol for EtherIp {
  fn protocol_number(&self) -> libc::c_int {
    PROTO_ETHERIP
  }
}

/// EtherIP socket
/// Large packets are fragmented by the kernel by default.
/// There is no need to `split` the `IpSocket` into a reader and a writer,
/// because it does not need to borrow self mutably to call `recv_from` and `send_to`.
/// Just wrap it in `Arc` and clone it.
#[derive(Debug)]
pub struct EtherIpSocket {
  inner: IpSocket<EtherIp>,
}

impl EtherIpSocket {
  /// Create a new EtherIP socket.
  pub fn new() -> std::io::Result<Self> {
    let inner = IpSocket::new(EtherIp ())?;
    Ok(Self {
      inner,
    })
  }

  /// Create a new EtherIP socket from a raw socket.
  pub fn from(socket: IpSocket<EtherIp>) -> Self {
    Self {
      inner: socket,
    }
  }

  /// Receive an EtherIP Datagram.
  pub async fn recv_from(&self, datagram: &mut EtherIpDatagram) -> std::io::Result<(usize, IpAddr)> {
    let (n, src_addr) = self.inner.recv_from(&mut datagram.data).await?;
    datagram.len = n;
    Ok((n, src_addr))
  }

  /// Send an EtherIP Datagram.
  pub async fn send_to(&self, datagram: &EtherIpDatagram, dst_addr: &IpAddr) -> std::io::Result<usize> {
    let data = if let Some(data) = datagram.datagram() {
      data
    } else {
      return Err(Error::new(ErrorKind::InvalidData, "Invalid EtherIP Datagram"));
    };
    self.inner.send_to(data, dst_addr).await
  }
}

/// EtherIP Datagram (excluding IP header)
#[derive(Debug, Clone)]
pub struct EtherIpDatagram {
  /// Datagram size (including EtherIP header and Ethernet frame)
  len: usize,

  /// EtherIP Datagram (excluding IP header)
  data: [u8; 65536]
}

impl EtherIpDatagram {
  pub fn new() -> Self {
    let mut datagram = Self {
      len: 2,
      data: [0; 65536]
    };
    datagram.data[0] = 0b0011_0000;
    datagram
  }

  /// Validate the EtherIP Datagram and get a reference to the encapsulated Ethernet frame.
  pub fn ethrnet_frame<'a>(&'a self) -> Option<&'a [u8]> {
    if self.len > self.data.len() {
      return None;
    }
    let buf: &'a [u8] = &self.data[..self.len];
    if buf.len() < 2 {
      return None;
    }
    let (etherip_header, eth_frame) = buf.split_at(2);
    if etherip_header != &[0b0011_0000, 0b0000_0000] {
      return None;
    }
    Some(eth_frame)
  }

  /// Get a mutable reference to the encapsulated Ethernet frame.
  pub fn ethrnet_frame_mut<'a>(&'a mut self) -> (EthernetFrameLength<'a>, &'a mut [u8]) {
    let (_etherip_header, eth_frame) = self.data.split_at_mut(2);
    (EthernetFrameLength {
      etherip_datagram_len: &mut self.len
    }, eth_frame)
  }

  /// Validate and get a reference to the EtherIP Datagram.
  pub fn datagram(&self) -> Option<&[u8]> {
    if self.len > self.data.len() {
      return None;
    }
    if self.len < 2 {
      return None;
    }
    if self.data[0] != 0b0011_0000 || self.data[1] != 0b0000_0000 {
      return None;
    }
    Some(&self.data[..self.len])
  }

  /// Get a mutable reference to the EtherIP Datagram.
  pub fn datagram_mut<'a>(&'a mut self) -> (EtherIpDatagramLength<'a>, &'a mut [u8]) {
    (EtherIpDatagramLength {
      etherip_datagram_len: &mut self.len
    }, &mut self.data)
  }
}

pub struct EthernetFrameLength<'a> {
  etherip_datagram_len: &'a mut usize,
}

impl EthernetFrameLength<'_> {
  pub fn set(&mut self, len: usize) {
    *self.etherip_datagram_len = len + 2;
  }
  
  pub fn get(&self) -> usize {
    *self.etherip_datagram_len - 2
  }
}

pub struct EtherIpDatagramLength<'a> {
  etherip_datagram_len: &'a mut usize,
}

impl EtherIpDatagramLength<'_> {
  pub fn set(&mut self, len: usize) {
    *self.etherip_datagram_len = len;
  }

  pub fn get(&self) -> usize {
    *self.etherip_datagram_len
  }
}
