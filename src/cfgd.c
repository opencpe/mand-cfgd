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
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <syslog.h>
#include <pwd.h>
#include <getopt.h>

#define USE_DEBUG

#include <ev.h>

#include <mand/logx.h>
#include <mand/binary.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include "cfgd.h"
#include "comm.h"

static const char _ident[] = "cfgd v" VERSION;
static const char _build[] = "build on " __DATE__ " " __TIME__ " with gcc " __VERSION__;

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

void sys_echo(const char *file, const char *fmt, ...)
{
	FILE *fout;
	va_list vlist;

	fout = fopen(file, "a+");
	if (!fout)
		return;

	va_start(vlist, fmt);
	vfprintf(fout, fmt, vlist);
	va_end(vlist);

	fclose(fout);
}

void set_ntp_server(const struct ntp_servers *servers)
{
	int i;

	vsystem("uci set system.ntp=timeserver");
	vasystem("uci set system.ntp.enable_server=%d", servers->enabled);
	vsystem("uci delete system.ntp.server");
	for (i = 0; i < servers->count; i++) {
		vasystem("uci add_list system.ntp.server='%s'", servers->server[i]);
	}
	vsystem("uci commit system.ntp");
	vsystem("/etc/init.d/sysntpd restart");
}

void set_dns(const struct string_list *search, const struct string_list *servers)
{
	int i;

	vsystem("uci delete dhcp.@dnsmasq[0].server");
	for (i = 0; i < servers->count; i++)
		vasystem("uci add_list dhcp.@dnsmasq[0].server='%s'", servers->s[i]);

	vsystem("uci set dhcp.@dnsmasq[0].add_local_domain=1");
	if (search->count != 0)
		vasystem("uci set dhcp.@dnsmasq[0].domain=\"%s\"", search->s[0]);
	vsystem("uci commit dhcp");
	vsystem("/etc/init.d/dnsmasq restart");
}

void set_ssh_keys(const char *name, const struct auth_ssh_key_list *list)
{
	int i;
	FILE *fout;
	char *s;
	struct passwd *pw;

	if (!(pw = getpwnam(name)))
		return;

	if (!pw->pw_dir || list->count == 0)
		return;

	if (asprintf(&s, "%s/.ssh/authorized_keys", pw->pw_dir) < 0)
		return;

	vasystem("mkdir -p %s/.ssh", pw->pw_dir);

	if (!(fout = fopen(s, "w"))) {
		free(s);
		return;
	}

	for (i = 0; i < list->count; i++) {
		fprintf(stderr, "    Key: %s %s %s\n", list->ssh[i].algo, list->ssh[i].data, list->ssh[i].name);
		fprintf(fout, "%s %s %s\n", list->ssh[i].algo, list->ssh[i].data, list->ssh[i].name);
	}
	fclose(fout);

	free(s);
}

void set_authentication(const struct auth_list *auth)
{
	int i;

	printf("Users: %d\n", auth->count);
	for (i = 0; i < auth->count; i++) {
		fprintf(stderr, "  User: %s, pass: %s, ssh: %d\n", auth->user[i].name, auth->user[i].password, auth->user[i].ssh.count);

		set_ssh_keys(auth->user[i].name, &auth->user[i].ssh);

	}
}

void set_if_addr(struct interface_list *info)
{
	int i, j;

	for (i = 0; i < info->count; i++) {
		const char *device = wrt_ifname(info->iface[i].name);
		char proc[PATH_MAX];

		vasystem("uci set network.%s.mtu=%d", info->iface[i].name, info->iface[i].ipv4.mtu);

		if (info->iface[i].ipv4.enabled) {
			for (j = 0; j < info->iface[i].ipv4.addr.count; j++) {
				vasystem("uci set network.%s.ipaddr=%s", info->iface[i].name, info->iface[i].ipv4.addr.ip[j].address);
				vasystem("uci set network.%s.netmask=%s", info->iface[i].name, info->iface[i].ipv4.addr.ip[j].value);
			}
		} else
			vasystem("uci delete network.%s.ipaddr", info->iface[i].name);

		if (info->iface[i].ipv6.enabled) {
			for (j = 0; j < info->iface[i].ipv6.addr.count; j++)
				vasystem("uci set network.%s.ip6addr=%s/%s", info->iface[i].name, info->iface[i].ipv6.addr.ip[j].address, info->iface[i].ipv6.addr.ip[j].value);
		} else
			vasystem("uci delete network.%s.if6addr", info->iface[i].name);

		vasystem("uci commit network.%s", info->iface[i].name);

		snprintf(proc, sizeof(proc), "/proc/sys/net/ipv4/conf/%s/forwarding", device);
		sys_echo(proc, "%u",  info->iface[i].name, info->iface[i].ipv4.forwarding);

		snprintf(proc, sizeof(proc), "/proc/sys/net/ipv6/conf/%s/forwarding", device);
		sys_echo(proc, "%u",  info->iface[i].name, info->iface[i].ipv6.forwarding);

		snprintf(proc, sizeof(proc), "/proc/sys/net/ipv6/conf/%s/mtu", device);
		sys_echo(proc, "%u",  info->iface[i].name, info->iface[i].ipv6.mtu);

	}
}

const char *wrt_ifname(const char *name)
{
	static char bridge[128];
	char *type;
	char *device;

	do {
		type = uci_get("network.%s.type", name);
		if (type && strcmp(type, "bridge") == 0) {
			snprintf(bridge, sizeof(bridge), "br-%s", name);
			return bridge;
		}

		device = uci_get("network.%s.ifname", name);
		if (!device || !device[0]) {
			fprintf(stderr, "wrt_ifname: could not map %s\n", name);
			return name;
		}

		name = device;
	} while (name[0] == '@');

	fprintf(stderr, "wrt_ifname: mapped to %s\n", name);

	return name;
}

void set_if_neigh(struct interface_list *info)
{
	int i, j;

	vsystem("ip neigh flush nud permanent");

	for (i = 0; i < info->count; i++) {
		for (j = 0; j < info->iface[i].ipv4.neigh.count; j++)
			vasystem("ip neigh replace %s lladdr %s nud permanent dev %s", info->iface[i].ipv4.neigh.ip[j].address, info->iface[i].ipv4.neigh.ip[j].value, wrt_ifname(info->iface[i].name));

		for (j = 0; j < info->iface[i].ipv6.neigh.count; j++)
			vasystem("ip neigh replace %s lladdr %s nud permanent dev %s", info->iface[i].ipv6.neigh.ip[j].address, info->iface[i].ipv6.neigh.ip[j].value, wrt_ifname(info->iface[i].name));
	}
}

void set_value(char *path, const char *str)
{
	fprintf(stderr, "Parameter \"%s\" changed to \"%s\"\n", path, str);

	if (strcmp(path, "system.hostname") == 0) {
		if (sethostname(str, strlen(str)) < 0)
			fprintf(stderr, "setting hostname failed with: %m\n");
		vasystem("uci set system.@system[0].hostname='%s'", str);
		vsystem("uci commit system.@system[0].hostname");
	}
}

static void sig_usr1(EV_P_ ev_signal *w, int revents)
{
}

static void sig_usr2(EV_P_ ev_signal *w, int revents)
{
	logx_level = logx_level == LOG_DEBUG ? LOG_INFO : LOG_DEBUG;
}

static void sig_pipe(EV_P_ ev_signal *w, int revents)
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

	ev_signal signal_usr1;
	ev_signal signal_usr2;
	ev_signal signal_pipe;

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

	ev_signal_init(&signal_usr1, sig_usr1, SIGUSR1);
        ev_signal_start(EV_DEFAULT_ &signal_usr1);

        ev_signal_init(&signal_usr2, sig_usr2, SIGUSR2);
        ev_signal_start(EV_DEFAULT_ &signal_usr2);

        ev_signal_init(&signal_pipe, sig_pipe, SIGPIPE);
        ev_signal_start(EV_DEFAULT_ &signal_pipe);

	init_comm(EV_DEFAULT);

	logx(LOG_NOTICE, "startup %s %s (pid %d)\n", _ident, _build, getpid());

	ev_run(EV_DEFAULT, 0);

        return 0;
}
