/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __COMM_H
#define __COMM_H

typedef void (comm_notify_cb)(void *);

void init_comm(struct event_base *base);
int comm_get_client_info(struct evp_client *client);

#endif
