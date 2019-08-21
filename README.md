# Lossless Gigabit Remote Packet Capture With Linux
Original work from https://staff.washington.edu/corey/gulp/ and http://blog.crox.net/archives/72-gulp-tcpdump-alternative-for-lossless-capture-on-Linux.html.
This repository is based on the latest patches from the original contributor (http://blog.crox.net/uploads/gulp-1.58-crox.tgz).

# Dependencies
* pcap.h
* cmake

Quick dependencies install command for Ubuntu (tested on Ubuntu 19.04)
```
sudo apt-get install libpcap-dev cmake
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
      -t        append a timestamp to the filename
      -C #      limit each pcap file in -o dir to # times the (-r #) size
      -G #      rotates the pcap file every # seconds
      -W #      overwrite pcap files in -o dir rather than start #+1 (max_files)
      -Z postrotate-command     run 'command file' after each rotation
    and some of academic interest only:
      -B        check if select(2) would ever have blocked on write
      -Y        avoid writes which would block
```

## Examples
Save captured network traffic to a file with UTC timestamp in file names e.g. `my_filename_20190821100215.pcap`
```
mkdir -p tmp
sudo bin/gulp -i enp111s0 -t -o tmp/ -n my_filename
```
 
Create a new file when the old grows over 100MB:
```
mkdir -p tmp
sudo bin/gulp -i enp111s0 -r 100 -C 1 -o tmp/ -n my_filename
```

Create a new file when the old grows over 100MB and include UTC timestamp in newly created file name:
```
mkdir -p tmp
sudo bin/gulp -i enp111s0 -r 100 -C 1 -o tmp/ -n my_filename -t
```

## Runing without root
If gulf executable is in `bin/gulp`:
```
sudo groupadd pcap
sudo usermod -a -G pcap $USER
sudo chgrp pcap bin/gulp
sudo setcap cap_ipc_lock,cap_sys_nice,cap_net_raw,cap_net_admin=eip bin/gulp
```
Short explanation why we need these capabilities:
* `cap_ipc_lock` is required because we're calling `mlock` which guarantees us that the buffer in RAM will stay in RAM
and will not be transferred to the SWAP area (in case another process would require more then available RAM) 
* `cap_sys_nice` sets the reader thread to high CPU priority
* `cap_net_raw` and `cap_net_admin` allow us to capture on the network device without being root