// -*- indent-tabs-mode: nil; tab-width: 4; -*-
// vim: set ts=4 sw=4 et ai :

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
use etherip::DefaultBuilder;
use etherip::DefaultParser;

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

#[derive(Debug, Clone)]
struct InterfaceState {
    tap: Arc<tap::Tap>,
    remote_addr: Arc<RwLock<Option<std::net::IpAddr>>>,
}

impl InterfaceState {
    fn new(tap: Arc<tap::Tap>) -> Self {
        Self {
            tap,
            remote_addr: Arc::new(RwLock::new(None)),
        }
    }

    #[inline]
    fn tap(&self) -> Arc<tap::Tap> {
        self.tap.clone()
    }

    #[inline]
    fn remote_addr(&self) -> Option<std::net::IpAddr> {
        *self.remote_addr.read()
    }

    #[inline]
    fn set_remote_addr(&self, remote_addr: std::net::IpAddr) {
        *self.remote_addr.write() = Some(remote_addr);
    }
}

#[derive(Debug, Clone)]
struct RemoteMap {
    map: Arc<RwLock<HashMap<std::net::IpAddr, Arc<tap::Tap>>>>,
}

impl RemoteMap {
    fn new() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn get(&self, remote_addr: &std::net::IpAddr) -> Option<Arc<tap::Tap>> {
        self.map.read().get(remote_addr).map(|tap| tap.clone())
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    syslog::init(syslog::Facility::LOG_DAEMON, log::LevelFilter::Info, Some(APP_NAME)).map_err(|e| anyhow::anyhow!("{}", e))?;
    let args = Args::parse();
    let config_path = args.config;
    let config = match load_config(&config_path).await {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Invalid or nonexistent configuration: {}", config_path.display());
            return Err(e);
        }
    };
    let config = Arc::new(RwLock::new(config));

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

    let interface_states = Arc::new(RwLock::new(HashMap::new() as HashMap<String, InterfaceState>));
    let remote_map = RemoteMap::new();
    let etherip_socket = EtherIpSocket::new()?;

    loop {
        let etherip_socket = etherip_socket.clone();
        let config = config.read();
        log::set_max_level(config.level_filter());

        let links = config.links.clone();
        drop(config);

        {
            let mut interface_states = interface_states.write();
            for (link_name, _) in &links {
                if !interface_states.contains_key(link_name) {
                    let tap = Arc::new(tap::Tap::new(link_name)?);
                    let interface_state = InterfaceState::new(tap);
                    interface_states.insert(link_name.clone(), interface_state);
                }
            }

            let to_remove: Vec<String> = interface_states.keys().filter(|link_name| !links.contains_key(*link_name)).cloned().collect();
            for link_name in to_remove {
                interface_states.remove(&link_name);
                tap::tap_del_ioctl(&link_name)?;
            }
        }

        let mut tasks = Vec::new();
        for (link_name, _) in &links {
            let interface_state = interface_states.read().get(link_name).unwrap().clone();
            let link_name = link_name.clone();
            let mut kill_receiver = kill_sender.subscribe();
            let tap = interface_state.tap();
            let etherip_socket = etherip_socket.clone();

            tasks.push(tokio::spawn(async move {
                select! {
                    _ = kill_receiver.recv() => {
                        log::debug!("TAP receiver {} killed", link_name);
                    },
                    _ = receive_from_tap(interface_state, tap, etherip_socket) => {
                        log::info!("TAP receiver {} exited", link_name);
                    }
                }
            }));
        }

        {
            let mut kill_receiver = kill_sender.subscribe();
            let remote_map = remote_map.clone();

            tasks.push(tokio::spawn(async move {
                select! {
                    _ = kill_receiver.recv() => {
                        log::debug!("EtherIP socket receiver killed");
                    },
                    _ = receive_from_etherip_socket(etherip_socket, remote_map) => {
                        log::info!("EtherIP socket receiver exited");
                    }
                }
            }));
        }

        {
            let mut kill_receiver = kill_sender.subscribe();
            let interface_states = interface_states.clone();
            let remote_map = remote_map.clone();

            tasks.push(tokio::spawn(async move {
                select! {
                    _ = kill_receiver.recv() => {
                        log::debug!("Remote address refresher killed");
                    },
                    _ = async move {
                        loop {
                            for link_name in links.keys() {
                                let link = links.get(link_name).unwrap();
                                match link.remote_addr().resolve(link.ip_version).await {
                                    Ok(remote_addr) => {
                                        let interface_state = interface_states.read().get(link_name).unwrap().clone();
                                        let old_remote_addr = interface_state.remote_addr();
                                        if old_remote_addr != Some(remote_addr) {
                                            interface_state.set_remote_addr(remote_addr);
                                            let mut map = remote_map.map.write();
                                            map.insert(remote_addr, interface_state.tap());
                                            if let Some(old_remote_addr) = old_remote_addr {
                                                map.remove(&old_remote_addr);
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        log::warn!("Failed to resolve remote address for {}: {}", link_name, e);
                                        continue;
                                    }
                                }
                            }

                            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                        }
                    } => {
                        log::info!("Remote address refresher exited");
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

async fn receive_from_tap(interface_state: InterfaceState, tap: Arc<tap::Tap>, etherip_socket: EtherIpSocket) -> Result<(), anyhow::Error> {
    let mut datagram = unsafe { DefaultBuilder::new() };
    loop {
        {
            let (len, mut buf) = datagram.ethernet_mut();
            *len = match tap.read(&mut buf).await {
                Ok(len) => len,
                Err(e) => {
                    log::warn!("Failed to read from TAP interface: {}", e);
                    continue;
                }
            };
        }

        if let Some(remote_addr) = interface_state.remote_addr() {
            let _ = etherip_socket.send_to(&datagram, remote_addr).await;
        } else {
            log::debug!("Sending a packet to an unknown remote address");
            continue;
        }
    }
}

async fn receive_from_etherip_socket(etherip_socket: EtherIpSocket, remote_map: RemoteMap) -> Result<(), anyhow::Error> {
    let mut datagram = unsafe { DefaultParser::new() };
    loop {
        let src = match etherip_socket.recv_from(&mut datagram).await {
            Ok(src) => src,
            Err(e) => {
                log::warn!("Failed to receive from EtherIP socket: {}", e);
                continue;
            }
        };

        let eth_frame = if let Some(eth_frame) = datagram.parse_ethernet() {
            eth_frame
        } else {
            log::debug!("Received a packet with an invalid EtherIP header from {}", src);
            continue;
        };

        match remote_map.get(&src) {
            Some(tap) => {
                let _ = tap.write(eth_frame).await;
            },
            None => {
                log::debug!("Received a packet from an unknown source IP address: {}", src);
                continue;
            }
        }
    }
}
