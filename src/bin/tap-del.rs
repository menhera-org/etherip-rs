// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=&2 sw=2 et ai :

use etherip::tap;

fn main() -> std::io::Result<()> {
  let ifname = std::env::args().nth(1).expect("Usage: tap-del <ifname>");

  tap::tap_del_ioctl(&ifname)
}
