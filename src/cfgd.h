/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __PROXY_H
#define __PROXY_H

#define CRLF  "\r\n"

#include <sys/queue.h>
#include <sys/tree.h>
#include <event.h>

struct evpbuffer {
	size_t size;
	size_t head;
	size_t tail;

	uint8_t buffer[];
};

#if USE_SPLICE
struct evpsplice {
	size_t len;

	int fdes[2];
};
#endif

struct header_line {
	SIMPLEQ_ENTRY(header_line) hlist;

	int len;
	char *value;
	char header[];
};

struct evproxy_connection {
	TAILQ_ENTRY(evproxy_connection) connection_queue;

	long request_id;

	const char *netns;
	int timeout;
	int client_fd;
	int server_fd;
	int connected;

	struct evpbuffer *buffer;
	struct evpbuffer *headers;
#if USE_SPLICE
	struct evpsplice splice;
#endif

	int direction;
	int read_state;
	int write_state;

	struct event connect_ev;
	struct event read_ev;
	struct event write_ev;

	uint32_t mark;

	int port;
	int ssl;
	char *proto;
	char *uri;
	int major, minor;
	int connect;
	int chunked;
	char *host;
	char *content_type;
	char *user_agent;
	char *referer;

	int keep_alive;

	struct header_line *content_length_header;

	long long in_content_length;
	long long out_content_length;
	long long content_read;
	long long content_sent;

	unsigned long long reqstart;

	int read_done;
	int read_pending;
	int close_pending;

	int insert_content_length;
	char *insert_content;

	struct in_addr remote_addr;
	struct in_addr host_addr;

	char *last_header;

	int flags;

	struct evp_client *client;

	char *request;
	struct hlist *request_headers;

	char *reply;
	int result;
	struct hlist *reply_headers;
};

void evp_set_session_state(uint64_t session_id, uint32_t state);
void evp_get_client_cb(struct evproxy_connection *evcon);

#endif
