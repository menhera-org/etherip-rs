// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=2 sw=2 et ai :

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
  pub fn remote_addr(&self) -> RemoteAddr {
    let ip_addr: Option<std::net::IpAddr> = self.remote.parse().ok();
    match ip_addr {
      Some(ip_addr) => RemoteAddr::Static(ip_addr),
      None => RemoteAddr::Dynamic(self.remote.clone()),
    }
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

pub enum RemoteAddr {
  Static(std::net::IpAddr),
  Dynamic(String),
}

impl RemoteAddr {
  pub async fn resolve(&self, ip_version: IpVersion) -> std::io::Result<std::net::IpAddr> {
    match self {
      RemoteAddr::Static(ip) => Ok(*ip),
      RemoteAddr::Dynamic(addr) => lookup_addr(addr, ip_version).await,
    }
  }
}
