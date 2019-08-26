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
