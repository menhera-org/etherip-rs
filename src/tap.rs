// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=2 sw=2 et ai :

use std::os::fd::AsRawFd;

use crate::libc;
use crate::nix;
use crate::tokio;

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;


pub const TUNSETIFF: libc::c_ulong = nix::request_code_write!(b'T', 202, std::mem::size_of::<libc::c_int>());
pub const TUNSETPERSIST: libc::c_ulong = nix::request_code_write!(b'T', 203, std::mem::size_of::<libc::c_int>());

pub const TUNDEV: *const libc::c_char = "/dev/net/tun\0".as_ptr() as *const libc::c_char;


fn ifname_to_cstring(ifname: &str) -> std::io::Result<std::ffi::CString> {
  if ifname.len() >= libc::IFNAMSIZ || ifname.len() == 0 {
    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "interface name too long or short"));
  }

  if ifname.contains('/') || ifname.contains(' ') || ifname.contains('\x0c') || ifname.contains('\n') || ifname.contains('\r') || ifname.contains('\t') || ifname.contains('\x0b'){
    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "interface name contains an invalid character"));
  }

  std::ffi::CString::new(ifname).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
}

/// Add a TAP interface with the given name.
pub fn tap_add_ioctl(ifname: &str) -> std::io::Result<()> {
  let ifname = ifname_to_cstring(ifname)?;

  let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
  unsafe {
    ifr.ifr_ifru.ifru_flags |= (libc::IFF_TAP | libc::IFF_NO_PI) as i16;
    libc::strncpy(ifr.ifr_name.as_mut_ptr(), ifname.as_ptr(), libc::IFNAMSIZ);

    let fd = libc::open(TUNDEV, libc::O_RDWR);
    if fd < 0 {
      return Err(std::io::Error::last_os_error());
    }

    let ret = libc::ioctl(fd, TUNSETIFF, &ifr);
    if ret < 0 {
      libc::close(fd);
      return Err(std::io::Error::last_os_error());
    }

    let ret = libc::ioctl(fd, TUNSETPERSIST, 1);
    if ret < 0 {
      libc::close(fd);
      return Err(std::io::Error::last_os_error());
    }

    libc::close(fd);
  }
  Ok(())
}

/// Delete a TAP interface with the given name.
pub fn tap_del_ioctl(ifname: &str) -> std::io::Result<()> {
  let ifname = ifname_to_cstring(ifname)?;

  let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
  unsafe {
    ifr.ifr_ifru.ifru_flags |= (libc::IFF_TAP | libc::IFF_NO_PI) as i16;
    libc::strncpy(ifr.ifr_name.as_mut_ptr(), ifname.as_ptr(), libc::IFNAMSIZ);

    let fd = libc::open(TUNDEV, libc::O_RDWR);
    if fd < 0 {
      return Err(std::io::Error::last_os_error());
    }

    let ret = libc::ioctl(fd, TUNSETIFF, &ifr);
    if ret < 0 {
      libc::close(fd);
      return Err(std::io::Error::last_os_error());
    }

    let ret = libc::ioctl(fd, TUNSETPERSIST, 0);
    if ret < 0 {
      libc::close(fd);
      return Err(std::io::Error::last_os_error());
    }

    libc::close(fd);
  }
  Ok(())
}


/// Raw TAP interface.
#[derive(Debug)]
pub struct RawTap {
  tap_fd: libc::c_int,
}

impl RawTap {
  pub fn new(ifname: &str) -> std::io::Result<Self> {
    let ifname = ifname_to_cstring(ifname)?;

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    unsafe {
      ifr.ifr_ifru.ifru_flags |= (libc::IFF_TAP | libc::IFF_NO_PI) as i16;
      libc::strncpy(ifr.ifr_name.as_mut_ptr(), ifname.as_ptr(), libc::IFNAMSIZ);

      let fd = libc::open(TUNDEV, libc::O_RDWR | libc::O_NONBLOCK);
      if fd < 0 {
        return Err(std::io::Error::last_os_error());
      }

      let ret = libc::ioctl(fd, TUNSETIFF, &ifr);
      if ret < 0 {
        libc::close(fd);
        return Err(std::io::Error::last_os_error());
      }

      let ret = libc::ioctl(fd, TUNSETPERSIST, 1);
      if ret < 0 {
        libc::close(fd);
        return Err(std::io::Error::last_os_error());
      }

      Ok(Self { tap_fd: fd })
    }
  }

  pub fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
    let ret = unsafe { libc::read(self.tap_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if ret < 0 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(ret as usize)
    }
  }

  pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
    let ret = unsafe { libc::write(self.tap_fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if ret < 0 {
      Err(std::io::Error::last_os_error())
    } else {
      Ok(ret as usize)
    }
  }
}

impl Drop for RawTap {
  fn drop(&mut self) {
    unsafe {
      libc::close(self.tap_fd);
    }
  }
}

impl AsRawFd for RawTap {
  fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
    self.tap_fd
  }
}

/// TAP interface.
/// There is no need to `split` the `IpSocket` into a reader and a writer,
/// because it does not need to borrow self mutably to call `recv_from` and `send_to`.
/// Just wrap it in `Arc` and clone it.
#[derive(Debug)]
pub struct Tap {
  inner: AsyncFd<RawTap>,
}

impl Tap {
  pub fn new(ifname: &str) -> std::io::Result<Self> {
    let tap = RawTap::new(ifname)?;
    let inner = AsyncFd::with_interest(tap, Interest::READABLE | Interest::WRITABLE)?;
    Ok(Self { inner })
  }

  pub async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
      let mut guard = self.inner.readable().await?;
      match guard.try_io(|inner| inner.get_ref().read(buf)) {
        Ok(result) => return result,
        Err(_would_block) => continue,
      }
    }
  }

  pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
    loop {
      let mut guard = self.inner.writable().await?;
      match guard.try_io(|inner| inner.get_ref().write(buf)) {
        Ok(result) => return result,
        Err(_would_block) => continue,
      }
    }
  }
}
