# Lossless Gigabit Remote Packet Capture With Linux
Original work from https://staff.washington.edu/corey/gulp/ and http://blog.crox.net/archives/72-gulp-tcpdump-alternative-for-lossless-capture-on-Linux.html.
This repository is based on the latest patches from the original contributor (http://blog.crox.net/uploads/gulp-1.58-crox.tgz).

# Dependencies
* pcap.h

Quick dependencies install command for Ubuntu (tested on Ubuntu 19.04)
```
sudo apt-get install libpcap-dev
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

## Runing without root
Currently not possible (see https://github.com/jmakov/gulp/issues/1)
```
sudo groupadd pcap
sudo usermod -a -G pcap $USER
sudo chgrp pcap gulp
sudo setcap cap_net_raw,cap_net_admin=eip gulp
```
