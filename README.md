# packet_goggles
For brief information about Layer 2, 3 and 4 limited details.

The "Packet Goggles" reveals basic details of ethernet, IP, and TCP details. The implementation is based on the "pcap" library.

1. Prerequisites
$ ```sudo apt update && sudo apt install libpcap-dev```

After installation, it can be verified.
```
$ apt info libpcap-dev
Package: libpcap-dev
Version: 1.9.1-3
Priority: optional
Section: libdevel
Source: libpcap
Origin: Ubuntu
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Original-Maintainer: Romain Francoise <rfrancoise@debian.org>
Bugs: https://bugs.launchpad.net/ubuntu/+filebug
Installed-Size: 20.5 kB
Depends: libpcap0.8-dev
Homepage: http://www.tcpdump.org/
Download-Size: 3,484 B
APT-Manual-Installed: yes
APT-Sources: http://fi.archive.ubuntu.com/ubuntu focal/main amd64 Packages
Description: development library for libpcap (transitional package)
 Empty package to facilitate upgrades, can be safely removed.
```
2. ```git clone packet_goggles```
3. ```make```
4. ```sudo ./packet_goggle```
