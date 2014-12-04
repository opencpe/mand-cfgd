# mand OpenWRT config agent

mand-cfg is a configration agent for mand that applies value changes to a OpenWRT
system though UCI and report statistic and runtime state values back to mand
though mand'd dmconfig RPC API.

It currently implements a limited set of values from IETF YANG NETCONF models for
the /system, /system-state, /interfaces and /interfaces-state sub-trees.

For applying and changing configutation values, OpenWRT's uci tool is used. For
reading interface configuration and status values, direct Linux system calls, procfs,
sysfs and netconf API's are used.

# Building and Install

## Requirements

- GNU make
- autotools
- autoconf
- libtool
- shtool
- gcc >= 4.7
- libev (including the event.h compatibility header, libev-libevent-dev package on Debian/Ubuntu)
- libralloc

## Build and Install

* rebuild automake and friends

	./autogen.sh

* configure

	./configure --prefix=/usr

* build and install

	make
	make install
