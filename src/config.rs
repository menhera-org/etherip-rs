// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=&2 sw=2 et ai :

//! Configuration for the EtherIP daemon.

use std::{collections::HashMap, path::Path};

use crate::tokio;
use crate::serde;
use crate::toml;
use crate::anyhow;

use serde::Deserialize;
use crate::log;
use log::LevelFilter;

/// Configuration for the EtherIP daemon.
#[derive(Deserialize, Clone, Debug)]
pub struct Config {
  pub log_level: LogLevel,
  pub links: HashMap<String, LinkConfig>,
}

impl Config {
  /// read the configuration from a file.
  pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
    let config_str = std::fs::read_to_string(path)?;
    let config = toml::from_str(&config_str)?;
    Ok(config)
  }

  /// read the configuration from a file asynchronously using tokio.
  pub async fn from_path_async<P: AsRef<Path>>(path: P) -> Result<Self, anyhow::Error> {
    let config_str = tokio::fs::read_to_string(path).await?;
    let config = toml::from_str(&config_str)?;
    Ok(config)
  }

  /// Get the log level as a `LevelFilter`.
  pub fn level_filter(&self) -> LevelFilter {
    self.log_level.into()
  }

  /// Get a map of remote IP addresses to link names.
  pub fn link_map(&self) -> AddrStringMap<String> {
    let mut pairs = Vec::new();
    for (name, link) in &self.links {
      pairs.push((link.remote_addr(), name.clone()));
    }
    AddrStringMap::new(pairs)
  }
}

/// Configuration for a link.
#[derive(Deserialize, Clone, Debug)]
pub struct LinkConfig {
  /// Remote IP address or hostname.
  pub remote: String,

  /// IP version
  pub ip_version: IpVersion,
}

impl LinkConfig {
  pub fn remote_addr(&self) -> AddrString {
    AddrString::new(self.remote.clone(), self.ip_version)
  }
}

/// IP version.
#[derive(Deserialize, Clone, Copy, Debug)]
pub enum IpVersion {
  V4,
  V6,
}

/// Log level.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Debug)]
pub enum LogLevel {
  Off,
  Error,
  Warn,
  Info,
  Debug,
  Trace,
}

impl Default for LogLevel {
  fn default() -> Self {
    LogLevel::Warn
  }
}

impl From<LogLevel> for LevelFilter {
  fn from(value: LogLevel) -> Self {
    match value {
      LogLevel::Off => LevelFilter::Off,
      LogLevel::Error => LevelFilter::Error,
      LogLevel::Warn => LevelFilter::Warn,
      LogLevel::Info => LevelFilter::Info,
      LogLevel::Debug => LevelFilter::Debug,
      LogLevel::Trace => LevelFilter::Trace,
    }
  }
}

impl From<LevelFilter> for LogLevel {
  fn from(value: LevelFilter) -> Self {
    match value {
      LevelFilter::Off => LogLevel::Off,
      LevelFilter::Error => LogLevel::Error,
      LevelFilter::Warn => LogLevel::Warn,
      LevelFilter::Info => LogLevel::Info,
      LevelFilter::Debug => LogLevel::Debug,
      LevelFilter::Trace => LogLevel::Trace,
    }
  }
}

pub async fn lookup_addr(addr: &str, ip_version: IpVersion) -> std::io::Result<std::net::IpAddr> {
  if let Ok(ip) = addr.parse() {
    return Ok(ip);
  }

  let addrs = tokio::net::lookup_host(format!("{}:0", addr)).await?;
  for addr in addrs {
    match ip_version {
      IpVersion::V4 => {
        if addr.is_ipv4() {
          return Ok(addr.ip());
        }
      }
      IpVersion::V6 => {
        if addr.is_ipv6() {
          return Ok(addr.ip());
        }
      }
    }
  }
  Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no address found"))
}

pub struct AddrString {
  /// IP address or hostname.
  addr_string: String,

  /// IP version
  ip_version: IpVersion,

  /// true if `addr_string` is an IP address.
  is_static_ip_addr: bool,

  /// IP address. Static if `is_static_ip_addr` is true, otherwise resolved.
  ip_addr: Option<std::net::IpAddr>,

  /// Time of the previous update.
  previous_update: Option<std::time::Instant>,
}

impl AddrString {
  pub fn new(addr_string: String, ip_version: IpVersion) -> Self {
    let ip_addr = addr_string.parse().ok();
    AddrString { addr_string, ip_version, is_static_ip_addr: ip_addr.is_some(), ip_addr, previous_update: None }
  }

  pub fn try_get_ip_addr(&self) -> Option<std::net::IpAddr> {
    self.ip_addr
  }

  pub async fn update_ip_addr(&mut self) -> std::io::Result<()> {
    if self.is_static_ip_addr {
      return Ok(());
    }

    if self.ip_addr.is_some() && self.previous_update.map_or(false, |t| t.elapsed().as_secs() < 60) {
      return Ok(());
    }

    self.ip_addr = Some(lookup_addr(&self.addr_string, self.ip_version).await?);
    self.previous_update = Some(std::time::Instant::now());
    Ok(())
  }

  pub fn is_static_ip_addr(&self) -> bool {
    self.is_static_ip_addr
  }
}

impl Default for AddrString {
  fn default() -> Self {
    AddrString {
      addr_string: "0.0.0.0".to_string(),
      ip_version: IpVersion::V4,
      is_static_ip_addr: true,
      ip_addr: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
      previous_update: None,
    }
  }
}

impl core::hash::Hash for AddrString {
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.addr_string.hash(state);
  }
}

pub struct AddrStringMap<T> {
  values: Vec<T>,
  addrs: Vec<AddrString>,
  addr_map: HashMap<std::net::IpAddr, usize>,
}

impl<T> AddrStringMap<T> {
  pub fn new(mut pairs: Vec<(AddrString, T)>) -> Self {
    let mut values = Vec::new();
    let mut addrs = Vec::new();
    let mut addr_map = HashMap::new();
    for (addr, value) in pairs.drain(..) {
      let i = addrs.len();
      addrs.push(addr);
      if let Some(ip_addr) = addrs[i].try_get_ip_addr() {
        addr_map.insert(ip_addr, i);
      }
      values.push(value);
    }
    AddrStringMap { values, addrs, addr_map }
  }

  pub fn get(&self, ip_addr: &std::net::IpAddr) -> Option<&T> {
    if let Some(i) = self.addr_map.get(ip_addr) {
      Some(&self.values[*i])
    } else {
      None
    }
  }

  pub async fn update(&mut self) -> std::io::Result<()> {
    for addr in &mut self.addrs {
      addr.update_ip_addr().await?;
    }
    self.addr_map.clear();
    for (i, addr) in self.addrs.iter().enumerate() {
      if let Some(ip_addr) = addr.try_get_ip_addr() {
        self.addr_map.insert(ip_addr, i);
      }
    }
    Ok(())
  }
}

