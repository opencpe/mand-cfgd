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
#include <libdmconfig/diammsg.h>
#include <libdmconfig/dmconfig.h>

#include "cfgd.h"
#include "comm.h"

static int session_valid = 0;
static DMCONTEXT dmCtx;

#define CB_ERR(...) {logx(LOG_ERR, __VA_ARGS__); return;}

#define HEARTBEAT_MS	2000
#define HEARTBEAT_LIMIT	3

struct hb_timer {
	ev_timer heartbeat;
	DMCONTEXT *dmCtx;
};

static struct hb_timer heartbeat_ev;

static void
heartbeatAnswerReceived(DMCONFIG_EVENT event,
			DMCONTEXT *dmCtx __attribute__((unused)),
			void *user_data __attribute__((unused)),
			uint32_t answer_rc,
			DIAM_AVPGRP *answer_grp __attribute__((unused)))
{
	static int missed;

	if (event == DMCONFIG_ANSWER_READY && answer_rc == RC_OK) {
		missed = 0;
	} else {
		/* most likely a socket communication or dmconfig session problem */
		logx(LOG_ERR, "%s(): event=%d, rc=%u (missed=%d)", __FUNCTION__,
		     event, answer_rc, missed);

		if (++missed > HEARTBEAT_LIMIT) {
			/* dump core and let us be restarted by tr069d if possible */
			logx(LOG_CRIT, "Too many heartbeat failures, aborting...");
			abort();
		}
	}
}

static void heartbeat_cb(EV_P_ ev_timer *w, int revents)
{
	struct hb_timer *ev = (struct hb_timer *)w;

	logx(LOG_DEBUG, "%s: event: %d", __func__, revents);

	if (dm_generic_register_request(ev->dmCtx, CMD_GW_HEARTBEAT, NULL,
				        heartbeatAnswerReceived, NULL))
		CB_ERR("Couldn't register GW_HEARTBEAT request.");

	ev_timer_again(EV_A_ w);

	logx(LOG_DEBUG, "%s: EXIT", __func__);
}

static void start_heartbeat(DMCONTEXT *dmCtx)
{
	if(dm_generic_register_request(dmCtx, CMD_GW_HEARTBEAT, NULL, NULL, NULL))
		CB_ERR("Couldn't register GW_HEARTBEAT request.");

	heartbeat_ev.dmCtx = dmCtx;
	ev_timer_init(&heartbeat_ev.heartbeat, heartbeat_cb, 0., HEARTBEAT_MS / 1000);
	ev_timer_again(dm_context_get_ev_loop(dmCtx), &heartbeat_ev.heartbeat);
}

static void
registeredNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__ ((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp)
{
        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't register gateway notifications.");
        logx(LOG_DEBUG, "Gateway notifications registered.");
}

static inline void decode_client_info(DIAM_AVPGRP *answer_grp)
{
        uint32_t        removed = 0;
        uint32_t        code;
        uint8_t         flags;
        uint32_t        vendor_id;
        void            *data;
        size_t          len;

	uint32_t	zone = 0;
	uint32_t	obj_id = 0;

	struct evp_client *client = NULL;

	while (!diam_avpgrp_get_avp(answer_grp, &code, &flags,
				    &vendor_id, &data, &len)) {
		
		logx(LOG_DEBUG, ": CMD_GW: got %d", code);
		switch (code) {
			
		case AVP_GW_ZONE:
			zone = diam_get_uint32_avp(data);
			logx(LOG_DEBUG, ": CMD_GW: zone: %d", zone);
			break;
			
		case AVP_GW_CLIENT_ID:
			obj_id = diam_get_uint32_avp(data);
			logx(LOG_DEBUG, ": CMD_GW: obj_id: %d", obj_id);
			break;
		}

		if (zone && obj_id)
			break;
	}
	diam_avpgrp_reset_avp(answer_grp);

	logx(LOG_DEBUG, "client zone: %d, obj_id: %d", zone, obj_id);
	if (zone && obj_id)
		client = get_client_by_oid((((uint64_t)zone) << 32) | obj_id);
	logx(LOG_DEBUG, "client: %p", client);
	if (!client)
		return;

	while (!diam_avpgrp_get_avp(answer_grp, &code, &flags,
				    &vendor_id, &data, &len)) {
		
		logx(LOG_DEBUG, ": CMD_GW: got %d", code);
		switch (code) {

		case AVP_GW_ZONE:
			client->zone = diam_get_uint32_avp(data);
			logx(LOG_DEBUG, ": CMD_GW: zone: %d", client->zone);
			break;

		case AVP_GW_CLIENT_ID:
			client->obj_id = diam_get_uint32_avp(data);
			logx(LOG_DEBUG, ": CMD_GW: obj_id: %d", client->obj_id);
			break;

		case AVP_GW_REMOVED:
			removed = diam_get_uint32_avp(data);
			logx(LOG_DEBUG, ": CMD_GW: removed: %d", removed);
			break;

		case AVP_GW_MACADDRESS: {
			char mac[18];

			diam_get_string_avp(mac, sizeof(mac), data, len);
			sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			       &client->mac[0], &client->mac[1], &client->mac[2],
			       &client->mac[3], &client->mac[4], &client->mac[5]);
			logx(LOG_DEBUG, ": CMD_GW: mac: %s", mac);
			break;
		}

		case AVP_GW_TOKEN:
			if (len) {
				talloc_free(client->token);
				client->token = talloc_strndup(client, data, len);
			}
			logx(LOG_DEBUG, ": CMD_GW: token: %s", client->token);
			break;

		case AVP_GW_ACCTSESSIONID:
			if (len) {
				talloc_free(client->acct_session_id);
				client->acct_session_id = talloc_strndup(client, data, len);
			}
			logx(LOG_DEBUG, ": CMD_GW: acctSessionId: %s", client->acct_session_id);
			break;
		case AVP_GW_SESSIONID:
			if (len) {
				talloc_free(client->session_id);
				client->session_id = talloc_strndup(client, data, len);
			}
			logx(LOG_DEBUG, ": CMD_GW: sessionId: %s", client->session_id);
			break;

		case AVP_GW_USERNAME:
			if (len) {
				talloc_free(client->uid);
				client->uid = talloc_strndup(client, data, len);
			}
			logx(LOG_DEBUG, ": CMD_GW: uid: %s", client->uid);
			break;

		case AVP_GW_LOCATIONID:
			if (len) {
				talloc_free(client->location_id);
				client->location_id = talloc_strndup(client, data, len);
			}
			logx(LOG_DEBUG, ": CMD_GW: loc_id: %s", client->location_id);
			break;

		case AVP_GW_AGENTCIRCUITID:
			if (len) {
				talloc_free(client->circuit_id);
				client->circuit_id = talloc_urlize(client, data, len);
			}
			logx(LOG_DEBUG, ": CMD_GW: circuit_id: %s", client->circuit_id);
			break;

		case AVP_GW_AGENTREMOTEID:
			if (len) {
				talloc_free(client->remote_id);
				client->remote_id = talloc_urlize(client, data, len);
			}
			logx(LOG_DEBUG, ": CMD_GW: remote_id: %s", client->remote_id);
			break;

		default:
			break;
		}
	}
	if (removed) {
		remove_client(client);
		talloc_unlink(NULL, client);
	}
}

static void
activeNotification(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__ ((unused)), DIAM_AVPGRP *grp)
{
        uint32_t        code;
        uint8_t         flags;
        uint32_t        vendor_id;
        void           *data;
        size_t          len;
	DIAM_AVPGRP    *answer;

        if (event != DMCONFIG_ANSWER_READY)
                CB_ERR("Error while retrieving an active notification.");
	

	while (!diam_avpgrp_get_avp(grp, &code, &flags,
				    &vendor_id, &data, &len)) {

		logx(LOG_DEBUG, "%s: code: %x, len: %zd\n", __FUNCTION__, code, len);
		if (code != AVP_CONTAINER || !len)
			break;

		answer = diam_decode_avpgrp(grp, data, len);
		if (!answer)
			break;

		logx(LOG_DEBUG, "%s: answer: %p\n", __FUNCTION__, answer);

		decode_client_info(answer);
	}
}

static void client_notify_cb(struct evp_client *client)
{
	struct evproxy_connection *evcon;

        evcon = TAILQ_FIRST(&client->connection_queue);
	while (evcon != TAILQ_END(&client->connection_queue)) {
		struct evproxy_connection *next = TAILQ_NEXT(evcon, connection_queue);

		logx(LOG_DEBUG, "[#%ld] %s exec evp_get_client_cb for client %p on evcon %p\n", evcon->request_id, __func__, client, evcon);
		evp_get_client_cb(evcon);
		evcon = next;
	}

	if (client->validation == CLNT_UNKNOWN) {
		/*
		 * client validation failed
		 *
		 * remove this client from the known clients list,
		 * the next http request will re-trigger the client info
		 */
		remove_client(client);
		talloc_unlink(NULL, client);
	}
}

static inline void decode_get_client_info(DIAM_AVPGRP *answer_grp, struct evp_client *client)
{
        uint32_t        code;
        uint8_t         flags;
        uint32_t        vendor_id;
        void            *data;
        size_t          len;

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT16 || len != sizeof(uint16_t))
		return;
	client->zone = diam_get_uint16_avp(data);
	logx(LOG_DEBUG, ": CMD_GW: zone: %d", client->zone);

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT16 || len != sizeof(uint16_t))
		return;
	client->obj_id = diam_get_uint16_avp(data);
	logx(LOG_DEBUG, ": CMD_GW: obj_id: %d", client->obj_id);

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_STRING)
		return;
	if (len) {
		char mac[18];

		diam_get_string_avp(mac, sizeof(mac), data, len);
		sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		       &client->mac[0], &client->mac[1], &client->mac[2],
		       &client->mac[3], &client->mac[4], &client->mac[5]);
		logx(LOG_DEBUG, ": CMD_GW: mac: %s", mac);
	}

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_STRING)
		return;
	if (len) {
		talloc_free(client->token);
		client->token = talloc_strndup(client, data, len);
	}
	logx(LOG_DEBUG, ": CMD_GW: token: %s", client->token);

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_STRING)
		return;
	if (len) {
		talloc_free(client->acct_session_id);
		client->acct_session_id = talloc_strndup(client, data, len);
	}
	logx(LOG_DEBUG, ": CMD_GW: acctSessionId: %s", client->acct_session_id);

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_STRING)
		return;
	if (len) {
		talloc_free(client->session_id);
		client->session_id = talloc_strndup(client, data, len);
	}
	logx(LOG_DEBUG, ": CMD_GW: sessionId: %s", client->session_id);

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_STRING)
		return;
	if (len) {
		talloc_free(client->uid);
		client->uid = talloc_strndup(client, data, len);
	}
	logx(LOG_DEBUG, ": CMD_GW: uid: %s", client->uid);

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_STRING)
		return;
	if (len) {
		talloc_free(client->location_id);
		client->location_id = talloc_strndup(client, data, len);
	}
	logx(LOG_DEBUG, ": CMD_GW: loc_id: %s", client->location_id);

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT16 || len != sizeof(uint16_t))
		return;
	logx(LOG_DEBUG, ": CMD_GW: accessclass: %d", diam_get_uint16_avp(data));

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_ADDRESS)
		return;

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_ADDRESS)
		return;

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_STRING)
		return;

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_DATE)
		return;

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT32 || len != sizeof(uint32_t))
		return;

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT32 || len != sizeof(uint32_t))
		return;

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT64 || len != sizeof(uint64_t))
		return;

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_UINT64 || len != sizeof(uint64_t))
		return;

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_BINARY)
		return;
	if (len) {
		talloc_free(client->circuit_id);
		client->circuit_id = talloc_urlize(client, data, len);
		logx(LOG_DEBUG, ": CMD_GW: circuit_id(%zd): %s", len, client->circuit_id);
	}

	if (diam_avpgrp_get_avp(answer_grp, &code, &flags, &vendor_id, &data, &len) ||
	    code != AVP_BINARY)
		return;
	if (len) {
		talloc_free(client->remote_id);
		client->remote_id = talloc_urlize(client, data, len);
		logx(LOG_DEBUG, ": CMD_GW: remote_id(%zd): %s", len, client->remote_id);
	}
}

static void
comm_get_client_info_event(DMCONFIG_EVENT event,
			   DMCONTEXT *dmCtx,
			   void *user_data,
			   uint32_t answer_rc,
			   DIAM_AVPGRP *answer_grp)
{
	struct evp_client *client = user_data;

        if (event == DMCONFIG_ANSWER_READY && answer_rc == RC_OK) {
		logx(LOG_DEBUG, "got client information.");
		logx(LOG_DEBUG, "client obj_id: %d, oid: %" PRIu64 "x", client->obj_id, client->oid);

		client->validation = CLNT_VALIDATED;
		decode_get_client_info(answer_grp, client);

		logx(LOG_DEBUG, "client zone: %d, obj_id: %d, oid: %" PRIu64 "x", client->zone, client->obj_id, client->oid);
		if (client->oid == 0) {
			client->oid = (((uint64_t)client->zone) << 32) | client->obj_id;
			logx(LOG_DEBUG, "add_client_by_oid: %" PRIu64 "x, %p", client->oid, client);
			add_client_by_oid(client);
		}

		DIAM_AVPGRP *grp;

		grp = dm_grp_new();
		if (grp) {
			diam_avpgrp_add_uint32(NULL, &grp, AVP_GW_ZONE, 0, VP_TRAVELPING, client->zone);
			diam_avpgrp_add_uint32(NULL, &grp, AVP_GW_CLIENT_ID, 0, VP_TRAVELPING, client->obj_id);
			
			if (dm_generic_register_request_bool_grp(dmCtx, CMD_GATEWAY_NOTIFY, 1 /* active notification */, grp, registeredNotify, NULL))
				CB_ERR("Couldn't register RECURSIVE PARAM NOTIFY request.");
			logx(LOG_DEBUG, "GATEWAY NOTIFY request registered.");
			
			dm_grp_free(grp);
		}
	} else {
		client->validation = CLNT_UNKNOWN;
		logx(LOG_ERR, "Couldn't get client information. (ev: %d, rc: %d)", event, answer_rc);
	}

	client_notify_cb(client);
}

int comm_get_client_info(struct evp_client *client)
{
	DIAM_AVPGRP     *grp;
	uint32_t        rc;
	
	if (!client)
		return 1;

	if (!(grp = dm_grp_new()))
		return 1;

	diam_avpgrp_add_uint16(NULL, &grp, AVP_UINT16, 0, VP_TRAVELPING, client->zone);
	diam_avpgrp_add_address(NULL, &grp, AVP_GW_IPADDRESS, 0, VP_TRAVELPING, AF_INET, &client->addr);
	diam_avpgrp_add_uint16(NULL, &grp, AVP_UINT16, 0, VP_TRAVELPING, 0);

	rc = dm_generic_register_request(&dmCtx, CMD_GW_GET_CLIENT, grp, comm_get_client_info_event, client);
	dm_grp_free(grp);

	if (rc == RC_OK)
		client->validation = CLNT_VALIDATION_PENDING;

	return (rc != RC_OK) ? 1 : 0;
}

static void
subscribedNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__ ((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp)
{
        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't subscribe gateway notifications.");
        logx(LOG_DEBUG, "Subscribed gateway notifications.");

	start_heartbeat(dmCtx);

}

static void
sessionStarted(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__ ((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp)
 {
        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't start session.");
        logx(LOG_DEBUG, "Session started.");

        if (dm_decode_start_session(dmCtx, answer_grp))
                CB_ERR("Couldn't decode sessionid.");

	session_valid = 1;

        if(dm_register_subscribe_gw_notify(dmCtx, activeNotification, NULL, subscribedNotify, NULL))
                CB_ERR("Couldn't register SUBSCRIBE GATEWAY NOTIFY request.");
        logx(LOG_DEBUG, "Gateway notification subscription request registered.");
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
