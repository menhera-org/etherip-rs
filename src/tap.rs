// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=&2 sw=2 et ai :

use crate::libc;
use crate::nix;


pub const TUNSETIFF: libc::c_ulong = nix::request_code_write!(b'T', 202, std::mem::size_of::<libc::c_int>());
pub const TUNSETPERSIST: libc::c_ulong = nix::request_code_write!(b'T', 203, std::mem::size_of::<libc::c_int>());

pub const TUNDEV: *const i8 = "/dev/net/tun\0".as_ptr() as *const i8;


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
