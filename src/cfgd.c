/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>

#define USE_DEBUG

#include <event.h>

#include <mand/logx.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "cfgd.h"
#include "comm.h"

static const char _ident[] = "cfgd v" VERSION;
static const char _build[] = "build on " __DATE__ " " __TIME__ " with gcc " __VERSION__;

struct event_base *ev_base;


int vsystem(const char *cmd)
{
        int rc = 0;
        int _errno;

        fprintf(stderr, "cmd=[%s]\n", cmd);

        errno = 0;
        rc = system(cmd);

        _errno = errno;
        fprintf(stderr, "cmd=[%s], rc=%d, error=%s\n", cmd, rc, strerror(_errno));
	errno = _errno;

        return rc;
}

int vasystem(const char *fmt, ...)
{
        va_list args;
        char    buf[1024];

        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        return vsystem(buf);
}

void set_ntp_server(const struct ntp_servers *servers)
{
	int i;

	vsystem("uci delete system.ntp.server");
	for (i = 0; i < servers->count; i++) {
		vasystem("uci add_list system.ntp.server='%s'", servers->server[i]);
	}
	vsystem("uci commit system.ntp.server");
	vsystem("/etc/init.d/sysntpd restart");
}

void set_dns(const struct string_list *search, const struct string_list *servers)
{
	char *s;
	int i;

	s = talloc_strdup(NULL, "uci set dnsmasq.server");
	for (i = 0; i < servers->count; i++) {
		s = talloc_asprintf_append(s, " %s", servers->s[i]);
	}
	talloc_free(s);

	if (search->count != 0)
		vasystem("uci set dhcp.@dnsmasq[0].domain %s", search->s[0]);
	vsystem("uci commit dhcp");
	vsystem("/etc/init.d/dnsmasq restart");
}

void set_if_addr(struct interface_list *info)
{
	int i, j;

	for (i = 0; i < info->count; i++) {
		for (j = 0; j < info->iface[i].ipv4.addr.count; j++) {
			vasystem("uci set network.%s.ipaddr=%s", info->iface[i].name, info->iface[i].ipv4.addr.ip[j].address);
			vasystem("uci set network.%s.netmask=%s", info->iface[i].name, info->iface[i].ipv4.addr.ip[j].value);
		}
		for (j = 0; j < info->iface[i].ipv6.addr.count; j++)
			vasystem("uci set network.%s.ip6addr=%s/%s", info->iface[i].name, info->iface[i].ipv6.addr.ip[j].address, info->iface[i].ipv6.addr.ip[j].value);
	}
}

void set_if_neigh(struct interface_list *info)
{
	int i, j;

	vsystem("ip neigh flush nud permanent");

	for (i = 0; i < info->count; i++) {
		for (j = 0; j < info->iface[i].ipv4.neigh.count; j++)
			vasystem("ip neigh add %s lladdr %s nud permanent dev %s", info->iface[i].ipv4.neigh.ip[j].address, info->iface[i].ipv4.neigh.ip[j].value, info->iface[i].name);

		for (j = 0; j < info->iface[i].ipv6.neigh.count; j++)
			vasystem("ip neigh add %s lladdr %s nud permanent dev %s", info->iface[i].ipv6.neigh.ip[j].address, info->iface[i].ipv6.neigh.ip[j].value, info->iface[i].name);
	}
}

void set_value(char *path, const char *str)
{
	fprintf(stderr, "Parameter \"%s\" changed to \"%s\"\n", path, str);

#if 0
	if (strncmp(path, "system.ntp.", 11) == 0) {
		char *s;
		long id = strtol(path + 11, &s, 10);

		if (s && strncmp(s, ".udp.address", 12) == 0) {
			vasystem("uci set system.ntp.@server[%ld]=%s", id - 1, str);
		}
	}
#endif
}

static void sig_usr1(int fd, short event, void *arg)
{
}

static void sig_usr2(int fd, short event, void *arg)
{
	logx_level = logx_level == LOG_DEBUG ? LOG_INFO : LOG_DEBUG;
}

static void sig_pipe(int fd, short event, void *arg)
{
	logx(LOG_DEBUG, "sig_pipe");
}

static void usage(void)
{
	printf("cfgd, Version: .....\n\n"
	       "Usage: cfg [OPTION...]\n\n"
	       "Options:\n\n"
	       "  -h                        this help\n"
	       "  -l, --log=IP              write log to syslog at this IP\n"
	       "  -x                        debug logging\n\n");

	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	const struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY
	};

	struct event signal_usr1;
	struct event signal_usr2;
	struct event signal_pipe;

	int c;

	/* unlimited size for cores */
	setrlimit(RLIMIT_CORE, &rlim);

	logx_level = LOG_INFO;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"log",       1, 0, 'l'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hl:x",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			break;

		case 'l': {
			struct in_addr addr;

			if (inet_aton(optarg, &addr) == 0) {
				fprintf(stderr, "Invalid IP address: '%s'\n", optarg);
				exit(EXIT_FAILURE);
			} else
				logx_remote(addr);
			break;
		}

		case 'x':
			logx_level = LOG_DEBUG;
			break;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	logx_open(basename(argv[0]), 0, LOG_DAEMON);

        ev_base = event_init();
        if (!ev_base)
		return 1;

        signal_set(&signal_usr1, SIGUSR1, sig_usr1, &signal_usr1);
        signal_add(&signal_usr1, NULL);
        signal_set(&signal_usr2, SIGUSR2, sig_usr2, &signal_usr2);
        signal_add(&signal_usr2, NULL);
        signal_set(&signal_pipe, SIGPIPE, sig_pipe, &signal_pipe);
        signal_add(&signal_pipe, NULL);

	init_comm(ev_base);

	logx(LOG_NOTICE, "startup %s %s (pid %d)\n", _ident, _build, getpid());

        event_base_loop(ev_base, 0);

        return 0;
}
