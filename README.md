# mand OpenWRT config agent

# Building and Install

## Requirements

- GNU make
- autotools
- autoconf
- libtool
- shtool
- gcc >= 4.7
- libev (including the event.h compatibility header, libev-libevent-dev package on Debian/Ubuntu)
- libtalloc

## Build and Install

* rebuild automake and friends

	./autogen.sh

* configure

	./configure --prefix=/usr

* build and install

	make 
	make install
