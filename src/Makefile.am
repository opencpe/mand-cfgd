# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

AM_CFLAGS = -D_GNU_SOURCE -Wall -I$(top_srcdir)/include/compat -I$(top_srcdir)/include -g -funit-at-a-time -std=gnu11 $(LIBNL3_CFLAGS)
AM_LDFLAGS= $(LIBNL3_LIBS)

bin_PROGRAMS = mand-cfgd

mand_cfgd_SOURCES = cfgd.c comm.c

DISTCLEANFILES = *~
