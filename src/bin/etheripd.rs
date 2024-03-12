// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=&2 sw=2 et ai :

//! etheripd - EtherIP daemon
//! Note that this does not daemonize, because it is intended to be run under a process supervisor like systemd.

use std::path::{Path, PathBuf};
use std::sync::Arc;

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

  loop {
    let config = config.read();
    log::set_max_level(config.level_filter());

    let links = config.links.clone();
    drop(config);

    let mut tasks = Vec::new();
    for (link_name, link_config) in links {
      let link_name = link_name.clone();
      let link_config = link_config.clone();
      let mut kill_receiver = kill_sender.subscribe();
      tasks.push(tokio::spawn(async move {
        select! {
          _ = kill_receiver.recv() => {
            log::debug!("Link {} killed", link_name);
          },
          _ = run_link(link_name.clone(), link_config) => {
            log::info!("Link {} exited", link_name);
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

async fn run_link(link_name: String, link_config: config::LinkConfig) -> Result<(), anyhow::Error> {
  drop(link_name);
  drop(link_config);
  Ok(())
}
