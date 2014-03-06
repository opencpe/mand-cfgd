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
		printf("unknown object: %s, type: %d\n", name ,type);
		break;
	}
	return RC_OK;
}

/** apply the values from system.ntp list to the UCI configuration
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

        while (decode_node_list("system.ntp", answer_grp, ntp_cb, &srvs) == RC_OK) {
        }

	set_ntp_server(&srvs);
}

static void
listSystemNtp(DMCONTEXT *dmCtx)
{
        if (dm_register_list(dmCtx, "system.ntp", 0, ntpListReceived, NULL))
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

	if (dm_expect_uint32_type(grp, AVP_EVENT_TYPE, VP_TRAVELPING, &type) != RC_OK
	    || dm_expect_string_type(grp, AVP_PATH, VP_TRAVELPING, &path) != RC_OK)
		return;

	printf("Event: %d on \"%s\"\n", type, path);
	logx(LOG_DEBUG, "Event: %d on \"%s\"\n", type, path);

	listSystemNtp(dmCtx);
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

        if(dm_register_recursive_param_notify(dmCtx, 1, "system.ntp", registeredParamNotify, NULL))
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
