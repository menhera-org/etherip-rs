
use crate::libc;

use std::ffi::c_int;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::os::fd::AsRawFd;
use std::mem::MaybeUninit;
use std::io::Error;
use std::hash::Hash;

use libc::socklen_t;
use tokio::io::unix::AsyncFd;

/// Raw IPv6 address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
#[repr(transparent)]
pub struct RawIpv6Addr {
    addr: [u8; 16],
}

impl Into<[u8; 16]> for RawIpv6Addr {
    fn into(self) -> [u8; 16] {
        unsafe { std::mem::transmute(self.addr) }
    }
}

impl From<[u8; 16]> for RawIpv6Addr {
    fn from(addr: [u8; 16]) -> Self {
        unsafe { std::mem::transmute(addr) }
    }
}

impl From<IpAddr> for RawIpv6Addr {
    fn from(addr: IpAddr) -> Self {
        let v6addr = match addr {
            IpAddr::V6(v6addr) => v6addr,
            IpAddr::V4(v4addr) => v4addr.to_ipv6_mapped(),
        };

        v6addr.octets().into()
    }
}

impl Into<IpAddr> for RawIpv6Addr {
    fn into(self) -> IpAddr {
        let v6addr = std::net::Ipv6Addr::from(self.addr);
        match v6addr.to_ipv4_mapped() {
            Some(v4addr) => IpAddr::V4(v4addr),
            None => IpAddr::V6(v6addr),
        }
    }
}

/// Configuration for Path MTU Discovery (PMTUD) for an `IpSocket`.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum FragmentConfig {
  /// Fragment large packets.
  Fragment,
  /// Reject large packets with EMSGSIZE.
  NoFragment,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub(crate) struct IpSocketInner<const P: c_int, const NONBLOCK: bool> {
    fd: c_int,
}

impl<const P: c_int> IpSocketInner<P, true> {
    #[inline]
    pub fn new() -> std::io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW | libc::SOCK_NONBLOCK, P) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { fd })
    }
}

impl<const P: c_int> IpSocketInner<P, false> {
    #[inline]
    pub fn new() -> std::io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_RAW, P) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { fd })
    }
}

impl<const P: c_int> TryFrom<IpSocketInner<P, true>> for IpSocketInner<P, false> {
    type Error = std::io::Error;

    fn try_from(inner: IpSocketInner<P, true>) -> Result<Self, Self::Error> {
        let flags = unsafe { libc::fcntl(inner.fd, libc::F_GETFL) };
        let flags = flags & !libc::O_NONBLOCK;
        let ret = unsafe { libc::fcntl(inner.fd, libc::F_SETFL, flags) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { fd: inner.fd })
    }
}

impl<const P: c_int> TryFrom<IpSocketInner<P, false>> for IpSocketInner<P, true> {
    type Error = std::io::Error;

    fn try_from(inner: IpSocketInner<P, false>) -> Result<Self, Self::Error> {
        let flags = unsafe { libc::fcntl(inner.fd, libc::F_GETFL) };
        let flags = flags | libc::O_NONBLOCK;
        let ret = unsafe { libc::fcntl(inner.fd, libc::F_SETFL, flags) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { fd: inner.fd })
    }
}

impl<const P: c_int, const NONBLOCK: bool> Drop for IpSocketInner<P, NONBLOCK> {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl<const P: c_int, const NONBLOCK: bool> AsRawFd for IpSocketInner<P, NONBLOCK> {
    fn as_raw_fd(&self) -> c_int {
        self.fd
    }
}

impl<const P: c_int, const NONBLOCK: bool> IpSocketInner<P, NONBLOCK> {
    #[inline]
    pub const fn protocol(&self) -> c_int {
        P
    }

    #[inline]
    pub fn set_fragment_config(&self, fragment_config: &FragmentConfig) -> std::io::Result<()> {
        let option = match fragment_config {
            FragmentConfig::Fragment => libc::IPV6_PMTUDISC_OMIT,
            FragmentConfig::NoFragment => libc::IPV6_PMTUDISC_DO,
        };
        let value = &option as *const c_int as *const libc::c_void;
        let len = std::mem::size_of_val(&option) as socklen_t;

        let ret = unsafe { libc::setsockopt(self.fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, value, len) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    #[inline]
    pub fn bind_unspecified(&self) -> std::io::Result<()> {
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = libc::AF_INET6 as u16;

        let addr_len = std::mem::size_of_val(&addr) as socklen_t;
        let ret = unsafe { libc::bind(self.fd, &addr as *const _ as *const libc::sockaddr, addr_len) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    #[inline]
    pub fn bind(&self, bind_addr: IpAddr) -> std::io::Result<()> {
        let bind_addr: RawIpv6Addr = bind_addr.into();

        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = libc::AF_INET6 as u16;
        addr.sin6_addr.s6_addr = bind_addr.into();

        let addr_len = std::mem::size_of_val(&addr) as socklen_t;
        let ret = unsafe { libc::bind(self.fd, &addr as *const _ as *const libc::sockaddr, addr_len) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    #[inline]
    pub fn bind_device(&self, device: Option<&[u8]>) -> std::io::Result<()> {
        if let Some(device) = device {
            let len = device.len() as socklen_t;
            let device = device.as_ptr() as *const libc::c_void;
            let ret = unsafe { libc::setsockopt(self.fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, device, len) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        } else {
            let ret = unsafe { libc::setsockopt(self.fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE, std::ptr::null(), 0) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        Ok(())
    }

    #[inline]
    pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, IpAddr)> {
        let mut sockaddr: MaybeUninit<libc::sockaddr_in6> = MaybeUninit::uninit();
        let n = {
            let sockaddr = unsafe { sockaddr.assume_init_mut() };
            let addr_len = std::mem::size_of_val(sockaddr) as socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    self.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    sockaddr as *mut _ as *mut libc::sockaddr,
                    &addr_len as *const _ as *mut _
                )
            };
            if n < 0 {
                return Err(Error::last_os_error());
            }

            n as usize
        };
        
        let sockaddr = unsafe { sockaddr.assume_init() };
        let addr: RawIpv6Addr = sockaddr.sin6_addr.s6_addr.into();
        Ok((n, addr.into()))
    }

    #[inline]
    pub fn send_to(&self, buf: &[u8], addr: IpAddr) -> std::io::Result<usize> {
        let addr: RawIpv6Addr = addr.into();

        let mut sockaddr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sockaddr.sin6_family = libc::AF_INET6 as u16;
        sockaddr.sin6_addr.s6_addr = addr.into();

        let addr_len = std::mem::size_of_val(&sockaddr) as socklen_t;
        let n = unsafe {
            libc::sendto(
                self.fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                &sockaddr as *const _ as *const libc::sockaddr,
                addr_len
            )
        };
        if n < 0 {
            return Err(Error::last_os_error());
        }

        Ok(n as usize)
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[repr(transparent)]
pub(crate) struct IpSocketWrapper<const P: c_int, const NONBLOCK: bool> {
    inner: Arc<IpSocketInner<P, NONBLOCK>>,
}

impl<const P: c_int, const NONBLOCK: bool> AsRawFd for IpSocketWrapper<P, NONBLOCK> {
    fn as_raw_fd(&self) -> c_int {
        self.inner.as_raw_fd()
    }
}

impl<const P: c_int, const NONBLOCK: bool> Deref for IpSocketWrapper<P, NONBLOCK> {
    type Target = IpSocketInner<P, NONBLOCK>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const P: c_int> IpSocketWrapper<P, true> {
    #[inline]
    pub fn new() -> std::io::Result<Self> {
        Ok(Self { inner: Arc::new(IpSocketInner::<P, true>::new()?) })
    }
}

impl<const P: c_int> IpSocketWrapper<P, false> {
    #[inline]
    pub fn new() -> std::io::Result<Self> {
        Ok(Self { inner: Arc::new(IpSocketInner::<P, false>::new()?) })
    }
}

pub trait IpSocket {
    fn protocol(&self) -> c_int;
    fn set_fragment_config(&self, fragment_config: &FragmentConfig) -> std::io::Result<()>;
    fn bind_unspecified(&self) -> std::io::Result<()>;
    fn bind(&self, bind_addr: IpAddr) -> std::io::Result<()>;
    fn bind_device(&self, device: Option<&[u8]>) -> std::io::Result<()>;
}

/// Blocking IPv6 socket.
/// 
/// P: Protocol number.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct BlockingIpSocket<const P: c_int> {
    inner: IpSocketWrapper<P, false>,
}

impl<const P: c_int> IpSocket for BlockingIpSocket<P> {
    #[inline]
    fn protocol(&self) -> c_int {
        self.inner.protocol()
    }

    #[inline]
    fn set_fragment_config(&self, fragment_config: &FragmentConfig) -> std::io::Result<()> {
        self.inner.set_fragment_config(fragment_config)
    }

    #[inline]
    fn bind_unspecified(&self) -> std::io::Result<()> {
        self.inner.bind_unspecified()
    }

    #[inline]
    fn bind(&self, bind_addr: IpAddr) -> std::io::Result<()> {
        self.inner.bind(bind_addr)
    }

    #[inline]
    fn bind_device(&self, device: Option<&[u8]>) -> std::io::Result<()> {
        self.inner.bind_device(device)
    }
}

impl<const P: c_int> BlockingIpSocket<P> {
    #[inline]
    pub fn new() -> std::io::Result<Self> {
        Ok(Self { inner: IpSocketWrapper::<P, false>::new()? })
    }

    #[inline]
    pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, IpAddr)> {
        self.inner.recv_from(buf)
    }

    #[inline]
    pub fn send_to(&self, buf: &[u8], addr: IpAddr) -> std::io::Result<usize> {
        self.inner.send_to(buf, addr)
    }
}

impl<const P: c_int> AsRawFd for BlockingIpSocket<P> {
    fn as_raw_fd(&self) -> c_int {
        self.inner.as_raw_fd()
    }
}

/// Non-blocking IPv6 socket.
/// There is no need to `split` the `IpSocket` into a reader and a writer,
/// because it does not need to borrow self mutably to call `recv_from` and `send_to`.
/// Also it implements Clone, so it can be cloned.
/// 
/// P: Protocol number.
#[derive(Debug, Clone)]
pub struct NonBlockingIpSocket<const P: c_int> {
    inner: Arc<AsyncFd<IpSocketWrapper<P, true>>>,
}

impl<const P: c_int> PartialEq for NonBlockingIpSocket<P> {
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_raw_fd() == other.inner.as_raw_fd()
    }
}

impl<const P: c_int> Eq for NonBlockingIpSocket<P> {}

impl<const P: c_int> PartialOrd for NonBlockingIpSocket<P> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.inner.as_raw_fd().partial_cmp(&other.inner.as_raw_fd())
    }
}

impl<const P: c_int> Ord for NonBlockingIpSocket<P> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.inner.as_raw_fd().cmp(&other.inner.as_raw_fd())
    }
}

impl<const P: c_int> Hash for NonBlockingIpSocket<P> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.inner.as_raw_fd().hash(state);
    }
}

impl<const P: c_int> IpSocket for NonBlockingIpSocket<P> {
    #[inline]
    fn protocol(&self) -> c_int {
        self.inner.get_ref().protocol()
    }

    #[inline]
    fn set_fragment_config(&self, fragment_config: &FragmentConfig) -> std::io::Result<()> {
        self.inner.get_ref().set_fragment_config(fragment_config)
    }

    #[inline]
    fn bind_unspecified(&self) -> std::io::Result<()> {
        self.inner.get_ref().bind_unspecified()
    }

    #[inline]
    fn bind(&self, bind_addr: IpAddr) -> std::io::Result<()> {
        self.inner.get_ref().bind(bind_addr)
    }

    #[inline]
    fn bind_device(&self, device: Option<&[u8]>) -> std::io::Result<()> {
        self.inner.get_ref().bind_device(device)
    }
}

impl<const P: c_int> NonBlockingIpSocket<P> {
    #[inline]
    pub fn new() -> std::io::Result<Self> {
        Ok(Self { inner: Arc::new(AsyncFd::new(IpSocketWrapper::<P, true>::new()?)?) })
    }

    #[inline]
    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, IpAddr)> {
        loop {
            let mut guard = self.inner.readable().await?;
            match guard.try_io(|inner| inner.get_ref().recv_from(buf)) {
                Ok(ret) => return ret,
                Err(_would_block) => {
                    continue;
                }
            }
        }
    }

    #[inline]
    pub async fn send_to(&self, buf: &[u8], addr: IpAddr) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, addr)) {
                Ok(ret) => return ret,
                Err(_would_block) => {
                    continue;
                }
            }
        }
    }
}
