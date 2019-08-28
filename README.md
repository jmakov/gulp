# Lossless Gigabit Remote Packet Capture With Linux
Original work from https://staff.washington.edu/corey/gulp/ and http://blog.crox.net/archives/72-gulp-tcpdump-alternative-for-lossless-capture-on-Linux.html.
This repository is based on the latest patches from the original contributor (http://blog.crox.net/uploads/gulp-1.58-crox.tgz).

# Features
* can run without root (see [running gulp without root](#Running-without-root))
* rotate files using UTC timestamps for new file names
* separate reading and writing thread for increased performance

# Getting started
## Installation
From project root run `./scripts/install.sh` (root required)

## Building manually
### Dependencies
* pcap.h
* cmake

Quick dependencies install command for Ubuntu (tested on Ubuntu 19.04)
```
sudo apt-get install libpcap-dev cmake
```

Build:
```shell script
mkdir cmake-build-release && cd cmake-build-release
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

# Usage
```
Usage: ./gulp [--help | options]
    --help      prints this usage summary
    supported options include:
      -d        decapsulate Cisco ERSPAN GRE packets (sets -f value)
      -f "..."  specify a pcap filter - see manpage and -d
      -i eth#|- specify ethernet capture interface or '-' for stdin
      -s #      specify packet capture "snapshot" length limit
      -F        skip the interface type (Ethernet) check
      -r #      specify ring buffer size in megabytes (1-1024)
      -c        just buffer stdin to stdout (works with arbitrary data)
      -x        request exclusive lock (to be the only instance running)
      -X        run even when locking would forbid it
      -v        print program version and exit
      -Vx...x   display packet loss and buffer use - see manpage
      -p #      specify full/empty polling interval in microseconds
      -q        suppress buffer full warnings
      -z #      specify write blocksize (even power of 2, default 65536)
    for long-term capture
      -o dir    redirect pcap output to a collection of files in dir
      -n name   filename (default: pcap)
      -t        append UTC timestamp to the filename
      -C #      limit each pcap file in -o dir to # times the (-r #) size
      -G #      rotates the pcap file every # seconds
      -W #      overwrite pcap files in -o dir rather than start #+1 (max_files)
      -Z postrotate-command     run 'command file' after each rotation
    and some of academic interest only:
      -B        check if select(2) would ever have blocked on write
      -Y        avoid writes which would block
```

## Examples
Assuming we already applied changes for [running gulp without root](#Running-without-root) otherwise we'll need to call
`sudo` before each command.

### Including UTC timestamp in file names
Save captured network traffic to a file with UTC timestamp in file name e.g. `my_filename_20190821100215.pcap`
```shell script
mkdir -p savedir
gulp -i eth0 -t -o savedir/ -n my_filename
```
### File rotation
Create a new file when the old grows over 100MB:
```shell script
mkdir -p savedir
gulp -i eth0 -r 100 -C 1 -o savedir/ -n my_filename
```

Create a new file when the old grows over 100MB and include UTC timestamp in newly created file names:
```shell script
mkdir -p savedir
gulp -i eth0 -r 100 -C 1 -o savedir/ -n my_filename -t
```

### Compress rotated files
postrotate.sh
```shell script
#!/usr/env bash

# gulp sends file name as an argumen to this script
IN_FN=$1
TMP_FN=$IN_FN.tmp
FIN_FN=$IN_FN.zst

zstd -q -19 --rm $IN_FN -o $TMP_FN
# signal with an atomic rename that the file is not being written to anymore
mv $TMP_FN $FIN_FN
```

We start gulp with the `-Z` flag:
```
mkdir -p savedir
gulp -i eth0 -t -r 100 -C 1 -n my_pcap_file -o savedir -Z postrotate.sh
```

## Running without root
```shell script
sudo groupadd pcap
sudo usermod -a -G pcap $USER
sudo mkdir -p /opt/gulp/bin
sudo cp build/bin/gulp /opt/gulp/bin
sudo chgrp pcap /opt/gulp/bin/gulp
sudo setcap cap_ipc_lock,cap_sys_nice,cap_net_raw,cap_net_admin=eip /opt/gulp/bin/gulp
```

Short explanation why we need these capabilities:
* `cap_ipc_lock` is required because we're calling `mlock` which guarantees us that the buffer in RAM will stay in RAM
and will not be transferred to the SWAP area (in case another process would require more then available RAM) 
* `cap_sys_nice` sets the reader thread to high CPU priority
* `cap_net_raw` and `cap_net_admin` allow us to capture on the network device without being root

## Tunables
From [Linux TCP tuning](https://www.cyberciti.biz/faq/linux-tcp-tuning/). Also see
[sysctl tweaks](https://wiki.mikejung.biz/Sysctl_tweaks#net.core.netdev_max_backlog)

Set the max OS send buffer size (wmem) and receive buffer size (rmem) to 12 MB for queues on all protocols. In other words set the amount of memory that is allocated for each TCP socket when it is opened or created while transferring files:
```shell script
# echo 'net.core.wmem_max=12582912' >> /etc/sysctl.conf
# echo 'net.core.rmem_max=12582912' >> /etc/sysctl.conf
```
You also need to set minimum size, initial size, and maximum size in bytes:
```shell script
# echo 'net.ipv4.tcp_rmem= 10240 87380 12582912' >> /etc/sysctl.conf
# echo 'net.ipv4.tcp_wmem= 10240 87380 12582912' >> /etc/sysctl.conf
```
Turn on window scaling which can be an option to enlarge the transfer window:
```shell script
# echo 'net.ipv4.tcp_window_scaling = 1' >> /etc/sysctl.conf
```
Enable timestamps as defined in RFC1323:
```shell script
# echo 'net.ipv4.tcp_timestamps = 1' >> /etc/sysctl.conf
```
Enable select acknowledgments:
```shell script
# echo 'net.ipv4.tcp_sack = 1' >> /etc/sysctl.conf
```
Set maximum number of packets, queued on the INPUT side, when the interface receives packets faster than kernel can 
process them.
```shell script
# echo 'net.core.netdev_max_backlog = 1000000' >> /etc/sysctl.conf
```
