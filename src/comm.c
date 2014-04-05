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

#ifdef HAVE_TALLOC_TALLOC_H
# include <talloc/talloc.h>
#else
# include <talloc.h>
#endif

#include <libdmconfig/codes.h>
#include <libdmconfig/dmmsg.h>
#include <libdmconfig/dmconfig.h>

#include "cfgd.h"
#include "comm.h"

static int session_valid = 0;
static DMCONTEXT dmCtx;

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
decode_node_list(const char *prefix, DM_AVPGRP *grp, DECODE_CB cb, void *cb_data)
{
	uint32_t r;
	DM_OBJ *container;
	char *name, *path;
	uint32_t type;

	if ((r = dm_expect_object(grp, &container)) != RC_OK
	    || (r = dm_expect_string_type(container, AVP_NODE_NAME, VP_TRAVELPING, &name)) != RC_OK
	    || (r = dm_expect_uint32_type(container, AVP_NODE_TYPE, VP_TRAVELPING, &type)) != RC_OK)
		return r;

	if (!(path = talloc_asprintf(container, "%s.%s", prefix, name)))
		return RC_ERR_ALLOC;

	switch (type) {
	case NODE_PARAMETER: {
		uint32_t code;
		uint32_t vendor_id;
		void *data;
		size_t size;

		if ((r = dm_expect_any(container, &code, &vendor_id, &data, &size)) != RC_OK)
			return r;

		cb(path, code, vendor_id, data, size, cb_data);
		break;
	}

	case NODE_TABLE:
	case NODE_OBJECT: {
		DM_OBJ *obj;

		cb(path, NODE_OBJECT, VP_TRAVELPING, NULL, 0, cb_data);

		if ((r = dm_expect_object(container, &obj)) != RC_OK)
			return r;

		while (decode_node_list(path, obj, cb, cb_data) == RC_OK) {
		}
		break;
	}

	default:
		printf("unknown object: %s, type: %d\n", path ,type);
		break;
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

	if (code == NODE_OBJECT)
		return;

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

static void
ntpListReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DM_AVPGRP *answer_grp)
{
	struct ntp_servers srvs;

        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't list object.\n");

	srvs.count = 0;
	srvs.server = talloc_array(answer_grp, char *, 16);
	if (!srvs.server)
		return;

        while (decode_node_list("system.ntp.server", answer_grp, ntp_cb, &srvs) == RC_OK) {
        }

	set_ntp_server(&srvs);
}

static void
listSystemNtp(DMCONTEXT *dmCtx)
{
        if (dm_register_list(dmCtx, "system.ntp.server", 0, ntpListReceived, NULL))
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

	if (code == NODE_OBJECT)
		return;

	if (!(s = strrchr(name, '.')))
		return;

	if (strncmp(s + 1, "search", 6) == 0) {
		add_string_list(&info->search, data, size);
	} else if (strncmp(s + 1, "address", 7) == 0) {
		add_string_list(&info->srvs, data, size);
	}
}

static void
dnsListReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DM_AVPGRP *answer_grp)
{
	struct dns_params info;

        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't list object.\n");

	new_string_list(answer_grp, &info.search);
	new_string_list(answer_grp, &info.srvs);

        while (decode_node_list("system.dns-resolver", answer_grp, dns_cb, &info) == RC_OK) {
        }

	set_dns(&info.search, &info.srvs);
}

static void
listSystemDns(DMCONTEXT *dmCtx)
{
        if (dm_register_list(dmCtx, "system.dns-resolver", 0, dnsListReceived, NULL))
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

	if (code == NODE_OBJECT)
		return;

	if (!(s = strchr(name + 1, '.')))
		return;

	if (strncmp(s + 1, "name", 4) == 0) {
		struct auth_user *d;

		printf("user (%d): %*s\n", info->count, size, data);
		if (!(d = add_var_list((struct var_list *)info, sizeof(struct auth_user))))
			return;

		new_var_list(info->ctx, (struct var_list *)&d->ssh, sizeof(struct auth_ssh_key_list));

		d->name = talloc_strndup(info->ctx, data, size);
	} else if (strncmp(s + 1, "password", 8) == 0) {
		printf("pass: %*s\n", size, data);
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
AuthListReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data, uint32_t answer_rc, DM_AVPGRP *answer_grp)
{
	struct auth_list auth;

        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't list object.\n");

	new_var_list(answer_grp, (struct var_list *)&auth, sizeof(struct auth_user));

        while (decode_node_list("", answer_grp, auth_cb, &auth) == RC_OK) {
        }

	set_authentication(&auth);
}

static void
listAuthentication(DMCONTEXT *dmCtx)
{
        if (dm_register_list(dmCtx, "system.authentication.user", 16, AuthListReceived, NULL))
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

	/* fprintf(stderr, "got : %s\n", name); */

	if (code == NODE_OBJECT)
		return;

	if (!(s = strchr(name + 1, '.')))
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
ifListReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data, uint32_t answer_rc, DM_AVPGRP *answer_grp)
{
	unsigned int flag = *(unsigned int *)user_data;
	struct interface_list info;

        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't list object.\n");

	new_var_list(answer_grp, (struct var_list *)&info, sizeof(struct interface));

        while (decode_node_list("", answer_grp, if_cb, &info) == RC_OK) {
        }

	if (flag | IF_NEIGH)
		set_if_neigh(&info);
	if (flag | IF_IP)
		set_if_addr(&info);
}

static void
listInterfaces(DMCONTEXT *dmCtx, unsigned int flags)
{
        if (dm_register_list(dmCtx, "interfaces.interface", 16, ifListReceived, &flags))
                CB_ERR("Couldn't register LIST request.\n");
}


static void
registeredParamNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__ ((unused)), uint32_t answer_rc, DM_AVPGRP *answer_grp)
{
        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't actice recursive param notifications.");
        logx(LOG_DEBUG, "Recursive param notification active.");
}

void
eventBroadcast(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), DM_AVPGRP *grp)
{
	uint32_t type;
	char *path;

        if (event != DMCONFIG_ANSWER_READY)
                CB_ERR("Error while retrieving an event broadcast.\n");

	printf("Broadcast....\n");

	if (dm_expect_uint32_type(grp, AVP_EVENT_TYPE, VP_TRAVELPING, &type) != RC_OK
	    || dm_expect_string_type(grp, AVP_PATH, VP_TRAVELPING, &path) != RC_OK)
		return;

	printf("Event: %d on \"%s\"\n", type, path);
	logx(LOG_DEBUG, "Event: %d on \"%s\"\n", type, path);

	if (strncmp(path, "system.ntp", 10) == 0)
		listSystemNtp(dmCtx);
	else if (strncmp(path, "system.dns-resolver", 19) == 0)
		listSystemDns(dmCtx);
	else if (strncmp(path, "system.authentication", 21) == 0)
		listAuthentication(dmCtx);
	else if (strncmp(path, "interfaces", 10) == 0)
		listInterfaces(dmCtx, IF_IP | IF_NEIGH);

}

void
activeNotification(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), DM_AVPGRP *grp)
{
        uint32_t type;

        if (event != DMCONFIG_ANSWER_READY)
                CB_ERR("Error while retrieving an active notification.\n");

        do {
                DM_AVPGRP *notify;

                if (dm_decode_notifications(grp, &type, &notify))
                        CB_ERR("Couldn't decode active notifications\n");

		if (type == NOTIFY_PARAMETER_CHANGED) {
                        char            *path, *str;

                        uint32_t        data_type, vendor_id;
                        uint8_t         flags;
                        void            *data;
                        size_t          len;

                        if (dm_decode_parameter_changed(notify, &path, &data_type))
                                CB_ERR("Couldn't decode active notifications\n");

                        if (dm_avpgrp_get_avp(notify, &data_type, &flags, &vendor_id, &data, &len) ||
                            dm_decode_unknown_as_string(data_type, data, len, &str)) {
                                free(path);
                                CB_ERR("Couldn't decode active notifications\n");
                        }

                        logx(LOG_DEBUG, "Notification: Parameter \"%s\" changed to \"%s\"\n", path, str);
			set_value(path, str);

                        free(path);
                        free(str);
                } else if (type != NOTIFY_NOTHING)
                        logx(LOG_DEBUG, "Notification: Warning, unknown type\n");

                dm_grp_free(notify);
        } while (type != NOTIFY_NOTHING);
}

static void
subscribedNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__ ((unused)), uint32_t answer_rc, DM_AVPGRP *answer_grp)
{
        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't subscribe notifications.");
        logx(LOG_DEBUG, "Subscribed notifications.");

        if(dm_register_recursive_param_notify(dmCtx, 1, "system.ntp.server", registeredParamNotify, NULL))
		CB_ERR("Couldn't register RECURSIVE PARAM NOTIFY request.");
        if(dm_register_recursive_param_notify(dmCtx, 1, "system.dns-resolver", registeredParamNotify, NULL))
		CB_ERR("Couldn't register RECURSIVE PARAM NOTIFY request.");
        logx(LOG_DEBUG, "RECURSIVE PARAM NOTIFY request registered.");
}

static void
sessionStarted(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__ ((unused)), uint32_t answer_rc, DM_AVPGRP *answer_grp)
 {
        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't start session.");
        logx(LOG_DEBUG, "Session started.");

        if (dm_decode_start_session(dmCtx, answer_grp))
                CB_ERR("Couldn't decode sessionid.");

	session_valid = 1;
	dm_register_event_handler(dmCtx, eventBroadcast, NULL);

        if(dm_register_subscribe_notify(dmCtx, activeNotification, NULL, subscribedNotify, NULL))
                CB_ERR("Couldn't register SUBSCRIBE NOTIFY request.");
        logx(LOG_DEBUG, "Notification subscription request registered.");

	listSystemNtp(dmCtx);
	listSystemDns(dmCtx);
	listAuthentication(dmCtx);
	listInterfaces(dmCtx, IF_IP | IF_NEIGH);
}

static void
socketConnected(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata __attribute__ ((unused)))
{
	struct timeval timeout = { .tv_sec = 120, .tv_usec = 0 };

        if (event != DMCONFIG_CONNECTED)
                CB_ERR("Connecting socket unsuccessful.");
        logx(LOG_DEBUG, "Socket connected.");

        if (dm_register_start_session(dmCtx, CMD_FLAG_READWRITE, &timeout, NULL, sessionStarted, NULL))
                CB_ERR("Couldn't register start session request.");
        logx(LOG_DEBUG, "Start session request registered.");
}

void init_comm(struct event_base *base)
{
        memset(&dmCtx, 0, sizeof(DMCONTEXT));
	dm_context_set_event_base(&dmCtx, base);

        if (dm_create_socket(&dmCtx, AF_INET)) {
                logx(LOG_DEBUG, "Couldn't create socket.");
                return;
        }
        logx(LOG_DEBUG, "Socket created.");

        if (dm_register_connect_callback(&dmCtx, AF_INET, socketConnected, NULL)) {
                logx(LOG_DEBUG, "Couldn't register connect callback or connecting unsuccessful.");
                dm_shutdown_socket(&dmCtx);
                return;
        }
        logx(LOG_DEBUG, "Connect callback registered.");
}
