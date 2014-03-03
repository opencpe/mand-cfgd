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

#define CB_ERR(...) {logx(LOG_ERR, __VA_ARGS__); return;}

static void
registeredParamNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__ ((unused)), uint32_t answer_rc, DM_AVPGRP *answer_grp)
{
        if (event != DMCONFIG_ANSWER_READY || answer_rc)
                CB_ERR("Couldn't actice recursive param notifications.");
        logx(LOG_DEBUG, "Recursive param notification active.");
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
                        CB_ERR("Couldn't decode active notifications\n")

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

        if(dm_register_subscribe_notify(dmCtx, activeNotification, NULL, subscribedNotify, NULL))
                CB_ERR("Couldn't register SUBSCRIBE NOTIFY request.");
        logx(LOG_DEBUG, "Notification subscription request registered.");
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
