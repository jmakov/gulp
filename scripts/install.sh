#!/usr/bin/env bash

sudo apt-get install libpcap-dev cmake

mkdir -p cmake-build-release && cd cmake-build-release
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .

if [ $(getent group pcap) ]; then
  echo "Group pcap already present, adding current user to it"
else
  echo "Creating group pcap"
  sudo groupadd pcap
fi
sudo usermod -a -G pcap $USER

sudo mkdir -p /opt/gulp/bin
sudo cp -rf bin/gulp /opt/gulp/bin
sudo chgrp pcap /opt/gulp/bin/gulp
sudo setcap cap_ipc_lock,cap_sys_nice,cap_net_raw,cap_net_admin=eip /opt/gulp/bin/gulp

read -p "Tune TCP settings in /etl/sYsctl.conf? [y/n]" -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  echo "### Added by puma-ETL ###" | $SYSCTL_APPEND_COMMAND
  echo 'net.core.wmem_max=12582912' | $SYSCTL_APPEND_COMMAND
  echo 'net.core.rmem_max=12582912' | $SYSCTL_APPEND_COMMAND
  echo 'net.ipv4.tcp_rmem= 10240 87380 12582912' | $SYSCTL_APPEND_COMMAND
  echo 'net.ipv4.tcp_wmem= 10240 87380 12582912' | $SYSCTL_APPEND_COMMAND
  echo 'net.ipv4.tcp_window_scaling = 1' | $SYSCTL_APPEND_COMMAND
  echo 'net.ipv4.tcp_timestamps = 1' | $SYSCTL_APPEND_COMMAND
  echo 'net.ipv4.tcp_sack = 1' | $SYSCTL_APPEND_COMMAND
  echo 'net.core.netdev_max_backlog = 1000000' | $SYSCTL_APPEND_COMMAND
  echo "### end of puma-ETL tunables" | $SYSCTL_APPEND_COMMAND

  # apply new settings
  sudo sysctl -p -q
fi
