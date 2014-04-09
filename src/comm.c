/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>

#include <ev.h>

#include "config.h"
#include <mand/logx.h>
#include <mand/binary.h>

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include <libdmconfig/codes.h>
#include <libdmconfig/dmmsg.h>
#include <libdmconfig/dmcontext.h>
#include <libdmconfig/dmconfig.h>
#include <libdmconfig/dm_dmconfig_rpc_stub.h>
#include <libdmconfig/dm_dmclient_rpc_impl.h>

#include "cfgd.h"
#include "comm.h"

#define IF_IP     (1 << 0)
#define IF_NEIGH  (1 << 1)

#define CB_ERR(...) \
	do {					\
		fprintf(stderr, __VA_ARGS__);	\
		fprintf(stderr, "\n");		\
		logx(LOG_ERR, __VA_ARGS__);	\
		return;				\
	} while (0)
#define CB_ERR_RET(ret, ...)			\
	do {					\
		fprintf(stderr, __VA_ARGS__);	\
		fprintf(stderr, "\n");		\
		logx(LOG_ERR, __VA_ARGS__);	\
		return ret;			\
	} while (0)

typedef void (*DECODE_CB)(const char *name, uint32_t code, uint32_t vendor_id, void *data, size_t size, void *cb_data);

static void new_var_list(void *ctx, struct var_list *list, size_t size)
{
	memset(list, 0, sizeof(struct var_list));
	list->ctx = ctx;
}

static void *add_var_list(struct var_list *list, size_t size)
{
	void *p;

	if ((list->count % 16) == 0) {
		if (!(list->data = talloc_realloc_size(list->ctx, list->data, size * (list->count + 16))))
			return NULL;
	}
	list->count++;

	p = ((void *)list->data) + (list->count - 1) * size;
	memset(p, 0, size);

	return p;
}

static void new_string_list(void *ctx, struct string_list *list)
{
	new_var_list(ctx, (struct var_list *)list, sizeof(char *));
}

static void add_string_list(struct string_list *list, const void *data, size_t size)
{
	void **d;

	if (!(d = add_var_list((struct var_list *)list, sizeof(char *))))
		return;

	*d = talloc_strndup(list->ctx, data, size);
}

uint32_t
decode_node_list(const char *prefix, DM2_AVPGRP *grp, DECODE_CB cb, void *cb_data)
{
	uint32_t r;
	DM2_AVPGRP container;
	uint32_t code;
	uint32_t vendor_id;
	void *data;
	size_t size;

	char *name, *path;
	uint16_t id;
	uint32_t type;

	if ((r = dm_expect_avp(grp, &code, &vendor_id, &data, &size)) != RC_OK)
		return r;

	if (vendor_id != VP_TRAVELPING)
		return RC_ERR_MISC;

	dm_init_avpgrp(grp->ctx, data, size, &container);

	switch (code) {
	case AVP_TABLE:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		while (decode_node_list(path, &container, cb, cb_data) == RC_OK) {
		}

		break;

	case AVP_INSTANCE:
		if ((r = dm_expect_uint16_type(&container, AVP_NAME, VP_TRAVELPING, &id)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%d", prefix, id)))
			return RC_ERR_ALLOC;

		while (decode_node_list(path, &container, cb, cb_data) == RC_OK) {
		}

		break;

	case AVP_OBJECT:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		while (decode_node_list(path, &container, cb, cb_data) == RC_OK) {
		}

		break;

	case AVP_ELEMENT:
		if ((r = dm_expect_string_type(&container, AVP_NAME, VP_TRAVELPING, &name)) != RC_OK
		    || (r = dm_expect_uint32_type(&container, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK)
			return r;

		if (!(path = talloc_asprintf(container.ctx, "%s.%s", prefix, name)))
			return RC_ERR_ALLOC;

		if ((r = dm_expect_avp(&container, &code, &vendor_id, &data, &size)) != RC_OK)
			return r;

		cb(path, code, vendor_id, data, size, cb_data);
		break;

	default:
		return RC_ERR_MISC;
	}

	return RC_OK;
}

/** apply the values from system.ntp.server list to the UCI configuration
 *
 * NOTE: this version cut some corners, more carefull check are needed when/if
 *       the datamodel also supports TCP
 */
void ntp_cb(const char *name, uint32_t code, uint32_t vendor_id, void *data, size_t size, void *cb_data)
{
	struct ntp_servers *srvs = (struct ntp_servers *)cb_data;
	const char *s;

	if (!(s = strrchr(name, '.')))
		return;

	if (strncmp(s + 1, "address", 7) == 0) {
		if ((srvs->count % 16) == 0) {
			srvs->server = talloc_realloc(NULL, srvs->server, char *, srvs->count + 16);
			if (!srvs->server)
				return;
		}
		srvs->server[srvs->count] = talloc_strndup(srvs->server, data, size);
		srvs->count++;
	}
}

void
ntpListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;
	struct ntp_servers srvs;

        if (event != DMCONFIG_ANSWER_READY)
                CB_ERR("Couldn't list object, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
                CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);

	srvs.count = 0;
	srvs.server = talloc_array(grp->ctx, char *, 16);
	if (!srvs.server)
		return;

        while (decode_node_list("", grp, ntp_cb, &srvs) == RC_OK) {
        }

	set_ntp_server(&srvs);
}

static void
listSystemNtp(DMCONTEXT *dmCtx)
{
        if (rpc_db_list_async(dmCtx, 0, "system.ntp.server", ntpListReceived, NULL))
                CB_ERR("Couldn't register LIST request.\n");
}


/** apply the values from system.dns.server list to the UCI configuration
 *
 * NOTE: this version cut some corners, more carefull check are needed when/if
 *       the datamodel also supports TCP
 */
struct dns_params {
	struct string_list search;
	struct string_list srvs;
};

void dns_cb(const char *name, uint32_t code, uint32_t vendor_id, void *data, size_t size, void *cb_data)
{
	struct dns_params *info = (struct dns_params *)cb_data;
	const char *s;

	if (!(s = strrchr(name, '.')))
		return;

	if (strncmp(s + 1, "search", 6) == 0) {
		add_string_list(&info->search, data, size);
	} else if (strncmp(s + 1, "address", 7) == 0) {
		add_string_list(&info->srvs, data, size);
	}
}

void
dnsListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;
	struct dns_params info;

        if (event != DMCONFIG_ANSWER_READY)
                CB_ERR("Couldn't list object, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
                CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);

	new_string_list(grp->ctx, &info.search);
	new_string_list(grp->ctx, &info.srvs);

        while (decode_node_list("", grp, dns_cb, &info) == RC_OK) {
        }

	set_dns(&info.search, &info.srvs);
}

static void
listSystemDns(DMCONTEXT *dmCtx)
{
        if (rpc_db_list_async(dmCtx, 0, "system.dns-resolver", dnsListReceived, NULL))
                CB_ERR("Couldn't register LIST request.\n");
}

/***************************************/

void ssh_key(const char *name, void *data, size_t size, struct auth_ssh_key_list *list)
{
	if (strncmp(name, "name", 4) == 0) {
		struct auth_ssh_key *d;

		if (!(d = add_var_list((struct var_list *)list, sizeof(struct auth_ssh_key))))
			return;

		d->name = talloc_strndup(list->ctx, data, size);
	} else if (strncmp(name, "algorithm", 9) == 0) {
		list->ssh[list->count - 1].algo = talloc_strndup(list->ctx, data, size);
	} else if (strncmp(name, "key-data", 8) == 0) {
		list->ssh[list->count - 1].data = talloc_size(list->ctx, size * 2);
		dm_to64(data, size, list->ssh[list->count - 1].data);
	}
}

void auth_cb(const char *name, uint32_t code, uint32_t vendor_id, void *data, size_t size, void *cb_data)
{
	struct auth_list *info = (struct auth_list *)cb_data;
	const char *s;

	if (!(s = strchr(name + 1, '.')))
		return;
	if (!(s = strchr(s + 1, '.')))
		return;

	if (strncmp(s + 1, "name", 4) == 0) {
		struct auth_user *d;

		printf("user (%d): %*s\n", info->count, (int)size, (char *)data);
		if (!(d = add_var_list((struct var_list *)info, sizeof(struct auth_user))))
			return;

		new_var_list(info->ctx, (struct var_list *)&d->ssh, sizeof(struct auth_ssh_key_list));

		d->name = talloc_strndup(info->ctx, data, size);
	} else if (strncmp(s + 1, "password", 8) == 0) {
		printf("pass: %*s\n", (int)size, (char *)data);
		info->user[info->count - 1].password = talloc_strndup(info->ctx, data, size);
	} else {
		if (strncmp(s + 1, "ssh-key.", 8) == 0) {
			if (!(s = strchr(s + 10, '.')))
				return;

			ssh_key(s + 1, data, size, &info->user[info->count - 1].ssh);
		}
	}
}

static void
AuthListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata __attribute__((unused)))
{
	uint32_t rc, answer_rc;
	struct auth_list auth;

        if (event != DMCONFIG_ANSWER_READY)
                CB_ERR("Couldn't list object, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
                CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);

	new_var_list(grp->ctx, (struct var_list *)&auth, sizeof(struct auth_user));

        while (decode_node_list("", grp, auth_cb, &auth) == RC_OK) {
        }

	set_authentication(&auth);
}

static void
listAuthentication(DMCONTEXT *dmCtx)
{
        if (rpc_db_list_async(dmCtx, 0, "system.authentication.user", AuthListReceived, NULL))
                CB_ERR("Couldn't register LIST request.\n");
}

/** apply the values from system.dns.server list to the UCI configuration
 *
 * NOTE: this version cut some corners, more carefull check are needed when/if
 *       the datamodel also supports TCP
 */
struct if_params {
	struct string_list search;
	struct string_list srvs;
};

void if_ip_addr(const char *name, void *data, size_t size, struct ip_list *list)
{
	const char *s;

	if (!(s = strchr(name + 1, '.')))
		return;

	if (strncmp("ip", s + 1, 2) == 0) {
		char b[INET6_ADDRSTRLEN];
		int af;
		struct in6_addr addr;
		struct ipaddr *d;

		if (!(d = add_var_list((struct var_list *)list, sizeof(struct ipaddr))))
			return;

		dm_get_address_avp(&af, &addr, sizeof(addr), data, size);
		inet_ntop(af, &addr, b, sizeof(b));
		d->af = af;
		d->address = talloc_strdup(list->ctx, b);
	} else if (size != 0 && strncmp("netmask", s + 1, 7) == 0) {
		struct ipaddr *d = list->ip + list->count - 1;

		d->value = talloc_asprintf(list->ctx, data, size);
	} else if (size != 0 && strncmp("prefix-length", s + 1, 13) == 0) {
		struct ipaddr *d = list->ip + list->count - 1;

		switch (d->af) {
		case AF_INET: {
			char b[INET_ADDRSTRLEN];
			struct in_addr addr;

			addr.s_addr = htonl(0xffffffff << (32 - dm_get_uint32_avp(data)));

			inet_ntop(AF_INET, &addr, b, sizeof(b));
			d->value = talloc_strdup(list->ctx, b);

			break;
		}
		case AF_INET6:
			d->value = talloc_asprintf(list->ctx, "%u", dm_get_uint32_avp(data));
			break;
		}
	}
}

void if_ip_neigh(const char *name, void *data, size_t size, struct ip_list *list)
{
	const char *s;

	if (!(s = strchr(name + 1, '.')))
		return;

	if (strncmp("ip", s + 1, 2) == 0) {
		char b[INET6_ADDRSTRLEN];
		int af;
		struct in6_addr addr;
		struct ipaddr *d;

		if (!(d = add_var_list((struct var_list *)list, sizeof(struct ipaddr))))
			return;

		dm_get_address_avp(&af, &addr, sizeof(addr), data, size);
		inet_ntop(af, &addr, b, sizeof(b));
		d->address = talloc_strdup(list->ctx, b);
	} else if (strncmp("link-layer-address", s + 1, 20) == 0) {
		struct ipaddr *d = list->ip + list->count - 1;

		d->value = talloc_strndup(list->ctx, data, size);
	}
}

void if_ip(const char *name, void *data, size_t size, struct if_ip *if_ip)
{
	if (strncmp("address", name, 7) == 0) {
		if_ip_addr(name + 8, data, size, &if_ip->addr);
	} else if (strncmp("neighbor", name, 8) == 0) {
		if_ip_neigh(name + 9, data, size, &if_ip->neigh);
	}
}

void if_cb(const char *name, uint32_t code, uint32_t vendor_id, void *data, size_t size, void *cb_data)
{
	struct interface_list *info = (struct interface_list *)cb_data;
	const char *s;

	if (!(s = strchr(name + 1, '.')))
		return;
	if (!(s = strchr(s + 1, '.')))
		return;

	if (strncmp(s + 1, "name", 4) == 0) {
		struct interface *d;

		if (!(d = add_var_list((struct var_list *)info, sizeof(struct interface))))
			return;

		new_var_list(info->ctx, (struct var_list *)&d->ipv4.addr, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv4.neigh, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv6.addr, sizeof(struct ip_list));
		new_var_list(info->ctx, (struct var_list *)&d->ipv6.neigh, sizeof(struct ip_list));

		d->name = talloc_strndup(info->ctx, data, size);
	} else if (strncmp(s + 1, "ipv4", 4) == 0) {
		if_ip(s + 6, data, size, &info->iface[info->count - 1].ipv4);
	} else if (strncmp(s + 1, "ipv6", 4) == 0) {
		if_ip(s + 6, data, size, &info->iface[info->count - 1].ipv6);
	}
}

static void
ifListReceived(DMCONTEXT *socket, DMCONFIG_EVENT event, DM2_AVPGRP *grp, void *userdata)
{
	unsigned int flag = *(unsigned int *)userdata;
	uint32_t rc, answer_rc;
	struct interface_list info;

        if (event != DMCONFIG_ANSWER_READY)
                CB_ERR("Couldn't list object, ev=%d.\n", event);

	if ((rc = dm_expect_uint32_type(grp, AVP_RC, VP_TRAVELPING, &answer_rc)) != RC_OK
	    || answer_rc != RC_OK)
                CB_ERR("Couldn't list object, rc=%d,%d.\n", rc, answer_rc);

	new_var_list(grp->ctx, (struct var_list *)&info, sizeof(struct interface));

        while (decode_node_list("", grp, if_cb, &info) == RC_OK) {
        }

	if (flag | IF_NEIGH)
		set_if_neigh(&info);
	if (flag | IF_IP)
		set_if_addr(&info);
}

static void
listInterfaces(DMCONTEXT *dmCtx, unsigned int flags)
{
        if (rpc_db_list_async(dmCtx, 16, "interfaces.interface", ifListReceived, &flags))
                CB_ERR("Couldn't register LIST request.\n");
}

static void
request_cb(DMCONTEXT *socket, DM_PACKET *pkt, DM2_AVPGRP *grp, void *userdata)
{
	DMC_REQUEST req;
	DM2_REQUEST *answer = NULL;

	req.hop2hop = dm_hop2hop_id(pkt);
	req.end2end = dm_end2end_id(pkt);
	req.code = dm_packet_code(pkt);

#ifdef LIBDMCONFIG_DEBUG
	fprintf(stderr, "Received %s:\n",
		dm_packet_flags(pkt) & CMD_FLAG_REQUEST ? "request" : "answer");
	dump_dm_packet(pkt);
#endif

	if ((rpc_dmclient_switch(socket, &req, grp, &answer)) == RC_ERR_ALLOC) {
		dm_context_shutdown(socket, DMCONFIG_OK);
		dm_context_release(socket);
		ev_break(socket->ev, EVBREAK_ALL);
		return;
	}

	if (answer)
		dm_enqueue(socket, answer, REPLY, NULL, NULL);
}

uint32_t rpc_client_active_notify(void *ctx, DM2_AVPGRP *obj)
{
        uint32_t rc;

        do {
		DM2_AVPGRP grp;
		uint32_t type;
		char *path;

		if ((rc = dm_expect_object(obj, &grp)) != RC_OK
		    || (rc = dm_expect_uint32_type(&grp, AVP_NOTIFY_TYPE, VP_TRAVELPING, &type)) != RC_OK
		    || (rc = dm_expect_string_type(&grp, AVP_PATH, VP_TRAVELPING, &path)) != RC_OK)
                        CB_ERR_RET(rc, "Couldn't decode active notifications, rc=%d\n", rc);

		switch (type) {
		case NOTIFY_INSTANCE_CREATED:
                        logx(LOG_DEBUG, "Notification: Instance \"%s\" created\n", path);
			break;

		case NOTIFY_INSTANCE_DELETED:
                        logx(LOG_DEBUG, "Notification: Instance \"%s\" deleted\n", path);
			break;

		case NOTIFY_PARAMETER_CHANGED: {
			struct dm2_avp avp;
			char *str;

			if ((rc = dm_expect_uint32_type(&grp, AVP_TYPE, VP_TRAVELPING, &type)) != RC_OK
			    || (rc = dm_expect_value(&grp, &avp)) != RC_OK
			    || (rc = dm_decode_unknown_as_string(type, avp.data, avp.size, &str)) != RC_OK)
				CB_ERR_RET(rc, "Couldn't decode parameter changed notifications, rc=%d\n", rc);

                        logx(LOG_DEBUG, "Notification: Parameter \"%s\" changed to \"%s\"\n", path, str);
			set_value(path, str);

			break;
                }
		default:
                        logx(LOG_DEBUG, "Notification: Warning, unknown type: %d\n", type);
			break;
		}
	} while ((rc = dm_expect_end(obj)) != RC_OK);

	return dm_expect_end(obj);
}

uint32_t rpc_client_event_broadcast(void *ctx, const char *path, uint32_t type)
{
	printf("Event: %d on \"%s\"\n", type, path);
	logx(LOG_DEBUG, "Event: %d on \"%s\"\n", type, path);

	if (strncmp(path, "system.ntp", 10) == 0)
		listSystemNtp(ctx);
	else if (strncmp(path, "system.dns-resolver", 19) == 0)
		listSystemDns(ctx);
	else if (strncmp(path, "system.authentication", 21) == 0)
		listAuthentication(ctx);
	else if (strncmp(path, "interfaces", 10) == 0)
		listInterfaces(ctx, IF_IP | IF_NEIGH);

	return RC_OK;
}

static uint32_t
socketConnected(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata __attribute__ ((unused)))
{
	uint32_t rc;

        if (event != DMCONFIG_CONNECTED) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
                CB_ERR_RET(RC_ERR_MISC, "Connecting socket unsuccessful.");
	}

        logx(LOG_DEBUG, "Socket connected.");

	if ((rc = rpc_startsession(dmCtx, CMD_FLAG_READWRITE, 0, NULL)) != RC_OK) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
                CB_ERR_RET(rc, "Couldn't register start session request, rc=%d.", rc);
	}

        logx(LOG_DEBUG, "Start session request registered.");

	if ((rc = rpc_subscribe_notify(dmCtx, NULL)) != RC_OK) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
                CB_ERR_RET(rc, "Couldn't register SUBSCRIBE NOTIFY request, rc=%d.", rc);
	}
        logx(LOG_DEBUG, "Notification subscription request registered.");

        if ((rc = rpc_recursive_param_notify(dmCtx, ACTIVE_NOTIFY, "system.ntp.server", NULL)) != RC_OK) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
		CB_ERR_RET(rc, "Couldn't register RECURSIVE PARAM NOTIFY request, rc=%d.", rc);
	}

	if ((rc = rpc_recursive_param_notify(dmCtx, ACTIVE_NOTIFY, "system.dns-resolver", NULL)) != RC_OK) {
		ev_break(dmCtx->ev, EVBREAK_ALL);
		CB_ERR_RET(rc, "Couldn't register RECURSIVE PARAM NOTIFY request, rc=%d.", rc);
	}

        logx(LOG_DEBUG, "RECURSIVE PARAM NOTIFY request registered.");

	listSystemNtp(dmCtx);
	listSystemDns(dmCtx);
	listAuthentication(dmCtx);
	listInterfaces(dmCtx, IF_IP | IF_NEIGH);

	return RC_OK;
}

void init_comm(struct ev_loop *loop)
{
	uint32_t rc;
	DMCONTEXT *ctx;

	if (!(ctx = dm_context_new())) {
                logx(LOG_DEBUG, "Couldn't create socket context.");
                return;
        }

	dm_context_init(ctx, loop, AF_INET, NULL, socketConnected, request_cb);

	/* connect */
	if ((rc = dm_connect_async(ctx)) != RC_OK) {
                logx(LOG_DEBUG, "Couldn't register connect callback or connecting unsuccessful, rc=%d.", rc);
		dm_context_shutdown(ctx, DMCONFIG_ERROR_CONNECTING);
		dm_context_release(ctx);
                return;
        }
	logx(LOG_DEBUG, "Connect callback registered.");
}
