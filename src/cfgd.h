/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __CFGD_H
#define __CFGD_H

#include <sys/queue.h>
#include <sys/tree.h>
#include <ev.h>

struct ntp_servers {
	void *ctx;
	int enabled;
	int count;
	char **server;
};

struct auth_ssh_key {
	char *name;
	char *algo;
	char *data;
};

struct auth_ssh_key_list {
	void *ctx;
	int count;
	struct auth_ssh_key *ssh;
};

struct auth_user {
	char *name;
	char *password;
	struct auth_ssh_key_list ssh;
};

struct auth_list {
	void *ctx;
	int count;
	struct auth_user *user;
};

struct var_list {
	void *ctx;
	int count;
	void *data;
};

struct string_list {
	void *ctx;
	int count;
	char **s;
};

struct ipaddr {
	int af;
	char *address;
	char *value;
};

struct ip_list {
	void *ctx;
	int count;
	struct ipaddr *ip;
};

struct if_ip {
	uint8_t enabled;
	uint8_t forwarding;
	uint32_t mtu;
	struct ip_list addr;
	struct ip_list neigh;
};

struct interface {
	char *name;
	struct if_ip ipv4;
	struct if_ip ipv6;
};

struct interface_list {
	void *ctx;
	int count;
	struct interface *iface;
};

const char *wrt_ifname(const char *name);

void set_ntp_server(const struct ntp_servers *servers);
void set_dns(const struct string_list *search, const struct string_list *servers);
void set_authentication(const struct auth_list *auth);
void set_if_addr(struct interface_list *info);
void set_if_neigh(struct interface_list *info);
void set_value(char *path, const char *str);

#endif
