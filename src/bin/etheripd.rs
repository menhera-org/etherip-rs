// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=&2 sw=2 et ai :

//! etheripd - EtherIP daemon
//! Note that this does not daemonize, because it is intended to be run under a process supervisor like systemd.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::collections::HashMap;

use etherip::tokio;
use etherip::log;
use etherip::syslog;
use etherip::anyhow;
use etherip::parking_lot;
use etherip::futures;

use parking_lot::RwLock;

use etherip::clap;
use clap::Parser;

use etherip::config;
use etherip::tap;

use etherip::EtherIpSocket;
use etherip::EtherIpDatagram;

use tokio::select;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;

const APP_NAME: &'static str = "etheripd";
const DEFAULT_CONFIG_PATH: &'static str = "/etc/etheripd/etheripd.toml";


#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
  #[clap(short = 'c', long, value_parser, default_value = DEFAULT_CONFIG_PATH)]
  config: PathBuf,
}

async fn load_config<P: AsRef<Path>>(config_path: P) -> Result<config::Config, anyhow::Error> {
  config::Config::from_path_async(config_path).await
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
  syslog::init(syslog::Facility::LOG_DAEMON, log::LevelFilter::Info, Some(APP_NAME)).map_err(|e| anyhow::anyhow!("{}", e))?;
  let args = Args::parse();
  let config_path = args.config;
  let config = Arc::new(RwLock::new(load_config(&config_path).await?));

  let mut hup_stream = signal(SignalKind::hangup())?;

  let (reload_sender, _) = broadcast::channel(16);
  let reload_sender_2 = reload_sender.clone();

  let (kill_sender, _) = broadcast::channel(16);

  let reloading_config = config.clone();

  // Thread that reloads the configuration when a HUP signal is received.
  tokio::spawn(async move {
    loop {
      hup_stream.recv().await;
      let new_config = load_config(&config_path).await;
      let mut config_changed = false;
      match new_config {
        Ok(new_config) => {
          let mut config = reloading_config.write();
          *config = new_config;
          config_changed = true;
          log::info!("Reloaded configuration from {}", config_path.display());
        },
        Err(e) => {
          log::warn!("Failed to reload configuration from {}: {}", config_path.display(), e);
        }
      }
      if config_changed {
        reload_sender_2.send(()).unwrap();
      }
    }
  });

  let tap_interfaces = RwLock::new(HashMap::new() as HashMap<String, Arc<tap::Tap>>);
  let etherip_socket = Arc::new(EtherIpSocket::new()?);

  loop {
    let etherip_socket = etherip_socket.clone();
    let config = config.read();
    log::set_max_level(config.level_filter());

    let links = config.links.clone();
    let link_map = config.link_map();
    drop(config);

    {
      let mut tap_interfaces = tap_interfaces.write();
      for (link_name, _link_config) in &links {
        if !tap_interfaces.contains_key(link_name) {
          let tap = tap::Tap::new(link_name)?;
          tap_interfaces.insert(link_name.clone(), Arc::new(tap));
        }
      }

      let to_remove: Vec<String> = tap_interfaces.keys().filter(|link_name| !links.contains_key(*link_name)).cloned().collect();
      for link_name in to_remove {
        tap_interfaces.remove(&link_name);
        tap::tap_del_ioctl(&link_name)?;
      }
    }

    let mut tasks = Vec::new();
    for (link_name, link_config) in &links {
      let link_name = link_name.clone();
      let link_config = link_config.clone();
      let mut kill_receiver = kill_sender.subscribe();
      let tap = tap_interfaces.read().get(&link_name).unwrap().clone();
      let etherip_socket = etherip_socket.clone();

      tasks.push(tokio::spawn(async move {
        select! {
          _ = kill_receiver.recv() => {
            log::debug!("TAP receiver {} killed", link_name);
          },
          _ = receive_from_tap(link_name.clone(), link_config, tap, etherip_socket) => {
            log::info!("TAP receiver {} exited", link_name);
          }
        }
      }));
    }

    {
      let mut kill_receiver = kill_sender.subscribe();
      let tap_interfaces = tap_interfaces.read().clone();

      tasks.push(tokio::spawn(async move {
        select! {
          _ = kill_receiver.recv() => {
            log::debug!("EtherIP socket receiver killed");
          },
          _ = receive_from_etherip_socket(etherip_socket, tap_interfaces, link_map) => {
            log::info!("EtherIP socket receiver exited");
          }
        }
      }));
    }

    reload_sender.subscribe().recv().await?;
    kill_sender.send(()).unwrap();
    let results = futures::future::join_all(tasks).await;
    for result in results {
      result?;
    }
  }
}

async fn receive_from_tap(link_name: String, link_config: config::LinkConfig, tap: Arc<tap::Tap>, etherip_socket: Arc<EtherIpSocket>) -> Result<(), anyhow::Error> {
  let mut datagram = EtherIpDatagram::new();
  loop {
    let (mut len_setter, mut buf) = datagram.ethrnet_frame_mut();
    match tap.read(&mut buf).await {
      Ok(len) => len_setter.set(len),
      Err(e) => {
        log::warn!("Failed to read from TAP interface {}: {}", link_name, e);
        continue;
      }
    }
    drop(len_setter);

    etherip_socket.send_to(&datagram, &link_config.remote).await?;
  }
}

async fn receive_from_etherip_socket(etherip_socket: Arc<EtherIpSocket>, tap_interfaces: HashMap<String, Arc<tap::Tap>>, link_map: HashMap<std::net::IpAddr, String>) -> Result<(), anyhow::Error> {
  let mut datagram = EtherIpDatagram::new();
  loop {
    let src = match etherip_socket.recv_from(&mut datagram).await {
      Ok((_, src)) => src,
      Err(e) => {
        log::warn!("Failed to receive from EtherIP socket: {}", e);
        continue;
      }
    };

    let eth_frame = if let Some(eth_frame) = datagram.ethrnet_frame() {
      eth_frame
    } else {
      log::debug!("Received a packet with an invalid EtherIP header from {}", src);
      continue;
    };

    match link_map.get(&src) {
      Some(link_name) => {
        let tap = tap_interfaces.get(link_name).ok_or_else(|| anyhow::anyhow!("Link {} does not exist", link_name))?;
        tap.write(eth_frame).await?;
      },
      None => {
        log::debug!("Received a packet from an unknown source IP address: {}", src);
        continue;
      }
    }
  }
}
