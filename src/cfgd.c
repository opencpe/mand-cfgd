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

#if !defined(SO_CONNTRACK_MARK)
#define SO_CONNTRACK_MARK  (SO_ORIGINAL_DST+1)
#endif

static int proxy_buffer_size = 1024 * 8;

#define PROXY_READ_TIMEOUT 60
#define PROXY_WRITE_TIMEOUT 60
#define PROXY_CONNECT_TIMEOUT 120

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#if USE_SPLICE
#define SPLICE_SIZE             16*4096
#define SPLICE_FULL_HINT        16*1448

#if !defined(SPLICE_F_NONBLOCK)

/* Flags for SPLICE and VMSPLICE.  */
# define SPLICE_F_MOVE          1       /* Move pages instead of copying.  */
# define SPLICE_F_NONBLOCK      2       /* Don't block on the pipe splicing
                                           (but we may still block on the fd
                                           we splice from/to).  */
# define SPLICE_F_MORE          4       /* Expect more data.  */
# define SPLICE_F_GIFT          8       /* Pages passed in are a gift.  */

/* Splice address range into a pipe.  */
static inline ssize_t vmsplice (int fdout, const struct iovec *iov,
				size_t count, unsigned int flags)
{
	return syscall(__NR_vmsplice, fdout, iov, count, flags);
}


/* Splice two files together.  */
static inline ssize_t splice (int fdin, loff_t *off_in, int fdout,
			      loff_t *offout, size_t len,
			      unsigned int flags)
{
	return syscall(__NR_splice, fdin, off_in, fdout, offout, len, flags);
}

/* In-kernel implementation of tee for pipe buffers.  */
static inline ssize_t tee (int fdin, int fdout, size_t len,
			   unsigned int flags)
{
	return syscall(__NR_tee, fdin, fdout, len, flags);
}

#endif
#endif

char *resolv_file = "/etc/resolv.conf";

long request_id = 0;

struct event_base *ev_base;

enum {
	EVCON_NONE = 0,
	EVCON_CLIENT,
	EVCON_SERVER,
};

enum {
	CLIENT2SERVER = 1,
	SERVER2CLIENT,
};

enum {
	EVP_OK = 0,
	EVP_ERROR,
	EVP_RETRY,
};

enum {
	IN_HEADERS = 1,
	IN_CONTENT,
};

enum {
	WRITE_DONE = 1,
	WRITE_NEED_MORE_SPACE,
};

enum evproxy_connection_error {
	EVCON_SHUTDOWN = 1,
        EVCON_READ_TIMEOUT,
        EVCON_READ_ERROR,
        EVCON_READ_EOF,
        EVCON_WRITE_TIMEOUT,
        EVCON_WRITE_ERROR,
        EVCON_WRITE_EOF,
        EVCON_CONNECT_TIMEOUT,
        EVCON_CONNECT_ERROR,
        EVCON_PROXY_INVALID_HEADER,
};

#define DBG_ENTRY(x) [x] = #x

const char *evproxy_connection_error_msg[] = {
	DBG_ENTRY(EVCON_SHUTDOWN),
	DBG_ENTRY(EVCON_READ_TIMEOUT),
	DBG_ENTRY(EVCON_READ_ERROR),
	DBG_ENTRY(EVCON_READ_EOF),
	DBG_ENTRY(EVCON_WRITE_TIMEOUT),
	DBG_ENTRY(EVCON_WRITE_ERROR),
	DBG_ENTRY(EVCON_WRITE_EOF),
	DBG_ENTRY(EVCON_CONNECT_TIMEOUT),
	DBG_ENTRY(EVCON_CONNECT_ERROR),
	DBG_ENTRY(EVCON_PROXY_INVALID_HEADER),
};

#define EVP_REQUEST_READ      0x01
#define EVP_HOST_RESOLVED     0x02
#define EVP_CLIENT_INFO       0x04

static int inet_socket(const char *netns);

static unsigned long long ltime(void)
{
        struct timeval tv;

        gettimeofday(&tv, NULL);
        return ((unsigned long long)tv.tv_sec) * 1000 + tv.tv_usec / 1000;
}

static int
evproxy_add_event(struct event *ev, int timeout, int default_timeout)
{
        if (timeout != 0) {
                struct timeval tv;

                timerclear(&tv);
                tv.tv_sec = timeout != -1 ? timeout : default_timeout;
                return event_add(ev, &tv);
        } else
                return event_add(ev, NULL);
}

static struct evpbuffer *evpbuffer_new(void *ctx, size_t size)
{
	struct evpbuffer *p;

	p = talloc_size(ctx, sizeof(struct evpbuffer) + size);
	if (!p)
		return NULL;

	memset(p, 0, sizeof(struct evpbuffer) + size);
	p->size = size;

	return p;
}

static inline uint8_t *evpbuffer_buffer(struct evpbuffer *p)
{
	return &p->buffer[p->head];
}

static inline size_t evpbuffer_size(struct evpbuffer *p)
{
	return p->size;
}

static inline size_t evpbuffer_length(struct evpbuffer *p)
{
	assert(p->tail >= p->head);

	return p->tail - p->head;
}

static inline size_t evpbuffer_space(struct evpbuffer *p)
{
	assert(p->size >= p->tail);

	return p->size - p->tail;
}

static inline void evpbuffer_swap(struct evpbuffer *a, struct evpbuffer *b)
{
	struct evpbuffer *t;

	t = a; a = b; b = t;
}

/**
 * add data to the start of a buffer
 */
static inline ssize_t evpbuffer_push(struct evpbuffer *p, const char *s, size_t len)
{
	if (p->head < len)
		return 0;

	p->head -= len;
	memmove(&p->buffer[p->head], s, len);

	return len;
}

/**
 * remove data from the start of a buffer
 */
static inline void evpbuffer_pull(struct evpbuffer *p, size_t len)
{
	if (evpbuffer_length(p) > len)
		p->head += len;
	else
		p->head = p->tail = 0;
}


/**
 * remove (cut) data from the middle of a buffer
 */
static inline void evpbuffer_cut(struct evpbuffer *p, char *s, size_t len)
{
	int pos;

	pos = s - (char *)&p->buffer[0];

	if (pos < p->head || pos > p->tail)
		/* pointer out of bounds */
		return;

	p->tail -= len;
	memmove(s, s + len, p->tail - pos);
}

/**
 * insert data in the middle of a buffer
 */
static inline int evpbuffer_insert(struct evpbuffer *p, char *s, size_t len)
{
	int pos;

	pos = s - (char *)&p->buffer[0];

	if (pos < p->head || pos > p->tail || p->tail + len > p->size)
		/* pointer out of bounds */
		return 0;

	p->tail += len;
	memmove(s + len, s, len);

	return len;
}

/**
 * add data to the end of a buffer
 */
static inline ssize_t evpbuffer_cat(struct evpbuffer *p, char *s, size_t len)
{
	len = len > evpbuffer_space(p) ? evpbuffer_space(p) : len;
	memmove(&p->buffer[p->tail], s, len);
	p->tail += len;

	return len;
}

/**
 * printf append data to a buffer
 */
static inline ssize_t evpbuffer_printf(struct evpbuffer *p, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

static inline ssize_t evpbuffer_printf(struct evpbuffer *p, const char *fmt, ...)
{
	ssize_t len;
	va_list ap;

	len = evpbuffer_space(p);
	if (len == 0)
		return 0;

	p->buffer[p->tail] = '\0';

	va_start(ap, fmt);
	vsnprintf((char *)&p->buffer[p->tail], p->size - p->tail, fmt, ap);
	va_end(ap);

	/* we can not trust snprintf to return the correct length */
	len = strlen((char *)&p->buffer[p->tail]);
	p->tail += len;

	return len;
}

static void evpbuffer_normalize(struct evpbuffer *p)
{
	size_t len;

	if (p->head == 0)
		return;

	len = evpbuffer_length(p);
	if (len != 0)
		memmove(p->buffer, &p->buffer[p->head], evpbuffer_length(p));

	p->head = 0;
	p->tail = len;
}

static ssize_t evpbuffer_read(struct evpbuffer *p, int fd)
{
	size_t space;
	ssize_t n;

	logx(LOG_DEBUG, "[%p] %s [%d]: buffer: %p head: %zd, tail: %zd\n", p, __func__, fd, p, p->head, p->tail);

	space = evpbuffer_space(p);
	if (!space)
		return -2;

	do {
		n = read(fd, &p->buffer[p->tail], space);
	} while (n < 0 && errno == EINTR);

	if (n > 0)
		p->tail += n;
	
	evpbuffer_normalize(p);

	if (n < 0)
		logx(LOG_DEBUG, "[%p] %s: res: %zd, errno: %m\n", p, __func__, n);
	else
		logx(LOG_DEBUG, "[%p] %s: res: %zd\n", p, __func__, n);

	return n;
}

static ssize_t evpbuffer_write(struct evpbuffer *p, int fd)
{
	ssize_t n;
	size_t len;

	logx(LOG_DEBUG, "[%p] %s [%d]: buffer: %p head: %zd, tail: %zd\n", p, __func__, fd, p, p->head, p->tail);

	len = evpbuffer_length(p);
	if (len == 0)
		return 0;

	n = write(fd, &p->buffer[p->head], len);
	if (n == len)
		p->head = p->tail = 0;
	else if (n > 0)
		p->head += n;

	evpbuffer_normalize(p);

	if (n < 0)
		logx(LOG_DEBUG, "[%p] %s: res: %zd, errno (%d): %m\n", p, __func__, n, errno);
	else
		logx(LOG_DEBUG, "[%p] %s: res: %zd\n", p, __func__, n);

	return n;
}

static void evpbuffer_clear(struct evpbuffer *p)
{
	p->head = p->tail = 0;
}

#if 0
static void evpbuffer_destroy(struct evpbuffer *p)
{
	evpbuffer_clear(p);
	talloc_free(p);
}
#endif

#if USE_SPLICE
static ssize_t evpbuffer_vmsplice(struct evpbuffer *p, struct evpsplice *s)
{
	ssize_t n;
	struct iovec io;

	logx(LOG_DEBUG, "[%p] %s [%d]: buffer: %p head: %zd, tail: %zd\n", p, __func__, s->fdes[1], p, p->head, p->tail);

	io.iov_base = &p->buffer[p->head];
	io.iov_len = evpbuffer_length(p);
	if (io.iov_len == 0)
		return 0;

	n = vmsplice(s->fdes[1], &io, 1, SPLICE_F_NONBLOCK);
	if (n < 0) {
		logx(LOG_DEBUG, "[%p] %s: res: %d, errno (%d): %m\n", p, __func__, n, errno);
	} else {
		logx(LOG_DEBUG, "[%p] %s: res: %d\n", p, __func__, n);
		if (n == evpbuffer_length(p))
			p->head = p->tail = 0;
		else if (n > 0)
			p->head += n;

		s->len += n;
		evpbuffer_normalize(p);
	}
	return n;
}

static int splice_init(struct evpsplice *p)
{
	int n;

	logx(LOG_DEBUG, "[%p] %s\n", p, __func__);

	n = pipe(p->fdes);
	if (n == 0) {
		if (fcntl(p->fdes[0], F_SETFL, O_NONBLOCK) == -1)
			logx(LOG_WARNING, "fcntl(O_NONBLOCK) on fdes[0]: %m\n");
		if (fcntl(p->fdes[1], F_SETFL, O_NONBLOCK) == -1)
			logx(LOG_WARNING, "fcntl(O_NONBLOCK) on fdes[1]: %m\n");
	}
	return n;
}

static void splice_close(struct evpsplice *p)
{
	logx(LOG_DEBUG, "[%p] %s\n", p, __func__);

	if (p->fdes[0] != 0) {
		close(p->fdes[0]);
		close(p->fdes[1]);
	}
}

static ssize_t splice_reader(struct evpsplice *p, int fd, ssize_t len)
{
	ssize_t n;

	logx(LOG_DEBUG, "[%p] %s [%d]: fdes[1]: [%d], len: %d\n", p, __func__, fd, p->fdes[1], len);

	if (len < 0 || len > SPLICE_SIZE)
		len = SPLICE_SIZE;

	n = splice(fd, NULL, p->fdes[1], NULL, len, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
	if (n < 0) {
		logx(LOG_DEBUG, "[%p] %s: res: %d, errno (%d): %m\n", p, __func__, n, errno);
		/* tread a EWOULDBLOCK as "pipe is full" is we are over the FULL_HINT */
		if (errno == EWOULDBLOCK && p->len >= SPLICE_FULL_HINT)
			n = -2;
	} else {
		logx(LOG_DEBUG, "[%p] %s: res: %d\n", p, __func__, n);
		p->len += n;
	}
	return n;
}

static ssize_t splice_writer(struct evpsplice *p, int fd)
{
	ssize_t n = 0;

	logx(LOG_DEBUG, "[%p] %s [%d]: fdes[0]: [%d]\n", p, __func__, fd, p->fdes[0]);

	n = splice(p->fdes[0], NULL, fd, NULL, SPLICE_SIZE, SPLICE_F_NONBLOCK);
	if (n < 0) {
		logx(LOG_DEBUG, "[%p] %s: res: %d, errno (%d): %m\n", p, __func__, n, errno);
	} else {
		logx(LOG_DEBUG, "[%p] %s: res: %d\n", p, __func__, n);
		p->len -= n;
	}

	return n;
}

static long splice_length(struct evpsplice *p)
{
	return p->len;
}

#endif

/************************************************************************************/
SIMPLEQ_HEAD(hlist, header_line);

static struct header_line *headers_append(struct hlist *head, const char *value, size_t len)
{
	char *p;
	struct header_line *line;

	if (!len || !value)
		return NULL;

	line = talloc_size(head, sizeof(struct header_line) + len + 8);      /* there might be a need to expand header lines later */
	if (!line)
		return NULL;

	memcpy(line->header, value, len);
	line->header[len] = '\0';

	p = strchr(line->header, ':');
	if (p) {
		*p++ = '\0';
		len--;
	}
	while (p && isspace(*p)) {
		p++;
		len--;
	}
	line->value = p;
	line->len = len;

	SIMPLEQ_INSERT_TAIL(head, line, hlist);

	return line;
}

static struct header_line *headers_append_new(struct hlist *head, const char *key, const char *fmt, ...)
	__attribute__ ((format (printf, 3, 4)));

static struct header_line *headers_append_new(struct hlist *head, const char *key, const char *fmt, ...)
{
	char buf[1024];
	size_t len, klen;
	struct header_line *line;
	va_list ap;

	strcpy(buf, key);
	klen = len = strlen(buf) + 1;

	va_start(ap, fmt);
	vsnprintf(buf + len, sizeof(buf) - len, fmt, ap);
	va_end(ap);

	/* MUST NOT TRUST snprintf */
	len += strlen(buf + len);

	line = talloc_size(head, sizeof(struct header_line) + len + 8);      /* there might be a need to expand header lines later */
	if (!line)
		return NULL;

	line->len = len - 1;
	memcpy(line->header, buf, len);
	line->header[len] = '\0';
	line->value = line->header + klen;

	SIMPLEQ_INSERT_TAIL(head, line, hlist);

	return line;
}

static inline void headers_free(struct hlist *head)
{
	talloc_free(head);
}

/************************************************************************************/

static char *readfile(char *name, ssize_t *len)
{
	char *p;
	int fd;
	struct stat fs;

	fd = open(name, O_RDONLY);
	if (fd == -1)
		return NULL;

	if (fstat(fd, &fs) != 0) {
		close(fd);
		return NULL;
	}

	p = talloc_size(NULL, fs.st_size);
	if (!p) {
		close(fd);
		return NULL;
	}
	*len = read(fd, p, fs.st_size);
	close(fd);

	return p;
}

/************************************************************************************/

#define INSERTIONS 16
struct {
	char *content;
	ssize_t len;
} insertions[INSERTIONS];

struct evproxy {
	struct event bind_ev;
	const char *netns;
};

static void init_sitelists(void);
static void init_insertions(void);
static void free_insertions(void);

/*
 * logfile stuff
 */

static int access_log_dest = 0;  /* 0 = NO LOG, 1 = FILE, 2 = STDERR, 3 = SYSLOG */
static char *access_log_file = "access.log";
static FILE *access_log = NULL;

static void sig_usr1(int fd, short event, void *arg)
{
	logx_close();
	if (access_log) {
		fclose(access_log);
		access_log = NULL;
	}

	init_sitelists();

	free_insertions();
	init_insertions();
}

static void evp_log_request(struct evproxy_connection *evcon, int verdict)
{
	const char *map[] = {
		[E_IGNORE]   = "IGNORE",
		[E_ACCEPT]   = "ACCEPT",
		[E_DENY]     = "DENY",
		[E_REDIRECT] = "REDIRECT",
		[E_PROXY]    = "PROXY",
		[E_ERROR]    = "ERROR",
	};

	char buf[64];
	char *ip;
	char uid[128] = "-";
	char sid[32] = "-";
	char cln[32] = "-";
	const char *vstr = map[E_ERROR];
	const uint8_t *mac = (uint8_t[6]){ 0, 0, 0, 0, 0, 0 };
	time_t t;
	int r;
	struct tm *tmp;

	if (access_log_dest == 0)
		return;

	t = time(NULL);
	tmp = localtime(&t);
	if (tmp == NULL) {
		perror("localtime");
		return;
	}
	
	if (evcon->client && evcon->client->uid)
		snprintf(uid, sizeof(uid), "%s", evcon->client->uid);

	if (evcon->client && evcon->client->session_id)
		snprintf(sid, sizeof(sid), "%s", evcon->client->session_id);

	if (evcon->in_content_length >= 0)
		snprintf(cln, sizeof(cln), "%lld", evcon->in_content_length);

	if (evcon->client)
		mac = evcon->client->mac;

	r = strftime(buf, sizeof(buf), "%d/%b/%Y:%H:%M:%S %z", tmp);
	buf[r] = '\0';

	ip = inet_ntoa(evcon->remote_addr);

	if (verdict >= E_IGNORE && verdict <= E_ERROR)
		vstr = map[verdict];

	switch (access_log_dest) {
	case 2: /* STDERR */
		if (!access_log)
			access_log = fdopen(STDERR_FILENO, "a");
		if (!access_log)
			break;

		/* FALL TROUGH */

	case 1: /* FILE */
		if (!access_log)
			access_log = fopen(access_log_file, "a");
		if (!access_log)
			break;
		fprintf(access_log, "%s - %s [%s] \"%s http%s://%s%s HTTP/%d.%d\" %d %s \"%s\" \"%s\" %s %02x:%02x:%02x:%02x:%02x:%02x %s\n", 
			ip,
			uid,
			buf,
			evcon->proto, evcon->ssl ? "s" : "", evcon->host, evcon->uri, evcon->major, evcon->minor,
			evcon->result,
			cln,
			evcon->referer ? evcon->referer : "-",
			evcon->user_agent ? evcon->user_agent : "-",
			sid,
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
			vstr);
		fflush(access_log);
		break;

	case 3: /* syslog */
		syslog(LOG_NOTICE | LOG_LOCAL7, "%s - %s [%s] \"%s http%s://%s%s HTTP/%d.%d\" %d %s \"%s\" \"%s\" %s %02x:%02x:%02x:%02x:%02x:%02x %s\n", 
		       ip,
		       uid,
		       buf,
		       evcon->proto, evcon->ssl ? "s" : "", evcon->host, evcon->uri, evcon->major, evcon->minor,
		       evcon->result,
		       cln,
		       evcon->referer ? evcon->referer : "-",
		       evcon->user_agent ? evcon->user_agent : "-",
		       sid,
		       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		       vstr);
		break;

	case 4: /* logx */
		logx(LOG_NOTICE | LOG_LOCAL7, "%s - %s [%s] \"%s http%s://%s%s HTTP/%d.%d\" %d %s \"%s\" \"%s\" %s %02x:%02x:%02x:%02x:%02x:%02x %s\n", 
		     ip,
		     uid,
		     buf,
		     evcon->proto, evcon->ssl ? "s" : "", evcon->host, evcon->uri, evcon->major, evcon->minor,
		     evcon->result,
		     cln,
		     evcon->referer ? evcon->referer : "-",
		     evcon->user_agent ? evcon->user_agent : "-",
		     sid,
		     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		     vstr);
		break;
	}
}

static void
evproxy_request_free(struct evproxy_connection *evcon)
{
	if (evcon->client) {
		logx(LOG_DEBUG, "[#%ld] %s remove evcon %p from client %p\n", evcon->request_id, __func__, evcon, evcon->client);
		TAILQ_REMOVE(&evcon->client->connection_queue, evcon, connection_queue);
	}
#if USE_SPLICE
	splice_close(&evcon->splice);
#endif

	talloc_free(evcon);
}

/** set the connection state to start
 */
static void evp_clear_req_state(struct evproxy_connection *evcon)
{
	evcon->read_state = IN_HEADERS;
	evcon->write_state = IN_HEADERS;

	evcon->read_done = 0;
	evcon->read_pending = 0;
	evcon->content_sent = 0;

	evcon->in_content_length = -1;
	evcon->out_content_length = -1;
	evcon->content_length_header = NULL;
	evcon->content_read = 0;
	evcon->content_sent = 0;

	evcon->insert_content_length = 0;
	evcon->insert_content = NULL;
}

/*
 * header functions
 */
static void evp_client_send_headers(struct evproxy_connection *evcon, struct evpbuffer *p);
static int evp_server_send_headers(struct evproxy_connection *evcon, struct evpbuffer *p);

static int evproxy_process_req_header(struct evproxy_connection *evcon, struct evpbuffer *p);
static int evproxy_process_reply_header(struct evproxy_connection *evcon, struct evpbuffer *p);

static void evproxy_check_connect(struct evproxy_connection *evcon);

/*
 * connection functions
 */
static void evp_set_connect(struct evproxy_connection *evcon, int fd, int timeout);
static void evp_clear_connect(struct evproxy_connection *evcon);
static void evp_connect_event(int fd, short what, void *arg);

static void evp_set_fwd_client2server(struct evproxy_connection *evcon, int fd, int timeout);
static void evp_set_fwd_server2client(struct evproxy_connection *evcon, int fd, int timeout);
static void evp_clear_fwd(struct evproxy_connection *evcon);

static void evp_fwd_client2server_event(int fd, short what, void *arg);
static void evp_fwd_server2client_event(int fd, short what, void *arg);

static void evp_set_read(struct evproxy_connection *evcon, int fd, int timeout);
static void evp_clear_read(struct evproxy_connection *evcon);
static void evp_read_event(int fd, short what, void *arg);

static void evp_exec_fwd_server2client_event(int fd, struct evproxy_connection *evcon)
{
	if (!event_pending(&evcon->write_ev, EV_WRITE | EV_TIMEOUT, NULL))
		evp_fwd_server2client_event(fd, EV_WRITE, evcon);
}

/*
 * close handling
 */

static void evp_shutdown_rd(int fd)
{
	ssize_t r;
	char buf[1024];

	shutdown(fd, SHUT_RD);

	do {
		r = read(fd, buf, sizeof(buf));
	} while (r > 0 || (r < 0 && errno == EINTR));
	logx(LOG_DEBUG, "%s [%d]: r: %zd, errno: %d (%m)\n", __func__, fd, r, errno);
}

static void evp_server_close(struct evproxy_connection *evcon, int fd, short reason)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

	/* we might not yet be connected, just do be sure */
	evp_clear_connect(evcon);

	/*
	 * direction doesn't matter, 
	 * there is no point in continue to read anything if the server is gone
	 */
	evp_clear_read(evcon);

	if (fd > 0) {
		evp_shutdown_rd(fd);
		close(fd);
		evcon->server_fd = -1;
		evcon->connected = 0;
	}

	if (evcon->client_fd <= 0) {
		/* no client connection, done */
		evproxy_request_free(evcon);
		return;
	}

	if (evcon->direction == SERVER2CLIENT) {
		evcon->read_done = 1;
		evcon->close_pending = 1;
		evp_shutdown_rd(evcon->client_fd);

		/*
		 * push a forward to get pending content to the client
		 */
		evp_exec_fwd_server2client_event(evcon->client_fd, evcon);
	} else {
		/* premature connection failure, kill the client */
		evp_clear_fwd(evcon);
		evp_shutdown_rd(evcon->client_fd);
		close(evcon->client_fd);
		evcon->client_fd = -1;

		evproxy_request_free(evcon);
	}
}

static void evp_gateway_error(struct evproxy_connection *evcon, int fd, short reason, int code)
{
	const char *error;

	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

	switch (code) {
	case 500:
		error = "Internal Server Error";
		break;

	case 501:
		error = "Not Implemented";
		break;

	case 502:
		error = "Bad Gateway";
		break;

	case 503:
		error = "Service Unavailable";
		break;

	case 504:
		error = "Gateway Timeout";
		break;

	case 505:
		error = "HTTP Version Not Supported";
		break;

	default:
		evp_server_close(evcon, fd, reason);
		return;
	}

	evcon->result = code;
	evp_log_request(evcon, E_ERROR);

	evpbuffer_clear(evcon->headers);
	evpbuffer_clear(evcon->buffer);
	evpbuffer_printf(evcon->buffer, 
			 "HTTP/1.0 %d %s" CRLF
			 "Content-Type: text/html" CRLF
			 "Connection: close" CRLF
			 "Cache-Control: private, no-cache, must-revalidate" CRLF
			 "Expires: Mon, 26 Jul 1997 05:00:00 GMT" CRLF
			 "Pragma: no-cache" CRLF
			 "" CRLF
			 "<HTML><BODY><H1>%s</H1></BODY></HTML>",
			 code, error, error);

	evcon->in_content_length = evcon->out_content_length = evcon->insert_content_length = -1;
	evcon->content_length_header = NULL;
	evcon->insert_content = NULL;

	evcon->direction = SERVER2CLIENT;
	evcon->write_state = IN_CONTENT;

	evcon->close_pending = 1;

	evp_server_close(evcon, fd, reason);
}

static void evp_client_close(struct evproxy_connection *evcon, int fd, short reason)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

	evp_shutdown_rd(fd);
	close(fd);
	evcon->client_fd = -1;

	/*
	 * if the client goes away, everything goes away,
	 * so we can unconditionaly clear the read events
	 */
	evp_clear_read(evcon);

	/*
	 * this would have to go, if we ever handle outstanding client2server action
	 */
	evp_clear_fwd(evcon);

	if (evcon->server_fd > 0) {
		/*
		 * with the client gone, there really is no need to continue talking to the server
		 */
		if (!evcon->connected)
			/* we have a socket, but are not connected yet, clear connect event! */
			evp_clear_connect(evcon);

		evp_shutdown_rd(evcon->server_fd);
		close(evcon->server_fd);
		evcon->server_fd = -1;
	}

	evproxy_request_free(evcon);
}

static void evp_close_on_read(struct evproxy_connection *evcon, int fd, short reason)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

	switch (evcon->direction) {
	case CLIENT2SERVER:
		evp_client_close(evcon, fd, reason);
		break;

	case SERVER2CLIENT:
		if (evcon->read_state == IN_HEADERS &&
		    (reason != EVCON_READ_EOF && reason != EVCON_WRITE_EOF)) {
			logx(LOG_DEBUG, "[#%ld] %s [%d], gateway error: %d\n", evcon->request_id, __func__, fd, reason);
			evp_gateway_error(evcon, fd, reason, (reason == EVCON_READ_TIMEOUT) ? 504 : 502);
		} else
			evp_server_close(evcon, fd, reason);
		break;
	}
}

/*
 * connect handling
 */

static void evp_set_connect(struct evproxy_connection *evcon, int fd, int timeout)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

        if (event_pending(&evcon->connect_ev, EV_WRITE | EV_TIMEOUT, NULL))
		event_del(&evcon->connect_ev);

	event_set(&evcon->connect_ev, fd, EV_WRITE, evp_connect_event, evcon);
	evproxy_add_event(&evcon->connect_ev, timeout, PROXY_CONNECT_TIMEOUT);
}

static void evp_clear_connect(struct evproxy_connection *evcon)
{
	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

        if (event_pending(&evcon->connect_ev, EV_WRITE | EV_TIMEOUT, NULL))
		event_del(&evcon->connect_ev);
}

static void
evp_connect_event(int fd, short what, void *arg)
{
	struct evproxy_connection *evcon = arg;

	logx(LOG_DEBUG, "[#%ld] %s [%d]: %d\n", evcon->request_id, __func__, fd, what);

	if (what == EV_TIMEOUT) {
		logx(LOG_DEBUG, "server read timeout\n");
		evp_gateway_error(evcon, fd, EVCON_CONNECT_TIMEOUT, 504);
		return;
	}

	int so_err, r;
	socklen_t optlen = sizeof(so_err);

	r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &optlen);
	if (r != 0 || so_err != 0) {
		if (r != 0)
			logx(LOG_DEBUG, "server connect error, getsockopt error: %d (%s)\n", errno, strerror(errno));
		if (so_err != 0)
			logx(LOG_DEBUG, "server connect error, so_error: %d (%s)\n", so_err, strerror(so_err));
		evp_gateway_error(evcon, fd, EVCON_CONNECT_TIMEOUT, 504);
		return;
	}

	/*
	 * we are successfully connected
	 */
	evcon->connected = 1;

	/*
	 * prepare requests headers and send them
	 */
	evp_fwd_client2server_event(fd, what, evcon);
}

/*
 * forward handling
 */

static void evp_clear_fwd(struct evproxy_connection *evcon)
{
	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

        if (event_pending(&evcon->write_ev, EV_WRITE | EV_TIMEOUT, NULL))
		event_del(&evcon->write_ev);
}

/*
 * client2server forward handling
 */

static void evp_set_fwd_client2server(struct evproxy_connection *evcon, int fd, int timeout)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

        if (event_pending(&evcon->write_ev, EV_WRITE | EV_TIMEOUT, NULL))
		event_del(&evcon->write_ev);

	event_set(&evcon->write_ev, fd, EV_WRITE, evp_fwd_client2server_event, evcon);
	evproxy_add_event(&evcon->write_ev, timeout, PROXY_WRITE_TIMEOUT);
}

static void evp_fwd_client2server_event(int fd, short what, void *arg)
{
	struct evproxy_connection *evcon = arg;

	logx(LOG_DEBUG, "[#%ld] %s [%d]: %d\n", evcon->request_id, __func__, fd, what);

	if (!evcon->connected) {
		logx(LOG_DEBUG, "[#%ld] %s [%d]: not connected yet\n", evcon->request_id, __func__, fd);
		return;
	}

	if (what == EV_TIMEOUT) {
		logx(LOG_DEBUG, "server write timeout\n");
		evp_server_close(evcon, fd, EVCON_WRITE_TIMEOUT);
		return;
	}

	switch (evcon->write_state) {
	case IN_HEADERS:
		evp_client_send_headers(evcon, evcon->headers);
		if (evpbuffer_length(evcon->headers) > 0)
			if (evpbuffer_write(evcon->headers, fd) == -1 &&
			    (errno != EINTR && errno != EAGAIN)) {
				logx(LOG_DEBUG, "IN_HEADERS, server write error: %m\n");
				evp_server_close(evcon, fd, EVCON_WRITE_ERROR);
				return;
			}
		if (evpbuffer_length(evcon->headers) > 0) {
			/*
			 * more data to send, shedule a write event
			 */
			evp_set_fwd_client2server(evcon, fd, PROXY_WRITE_TIMEOUT);
			break;
		}
		evcon->write_state = IN_CONTENT;
		/* FALL THROUGH */

	case IN_CONTENT:
#if USE_SPLICE
		/* push the remaining data from the header read into the pipe */
		if (evpbuffer_length(evcon->buffer) > 0) {
			int n;

			n = evpbuffer_vmsplice(evcon->buffer, &evcon->splice);

			if (n == -1 &&
			    (errno != EINTR && errno != EAGAIN)) {
				logx(LOG_DEBUG, "IN_CONTENT, server write error: %m\n");
				evp_server_close(evcon, fd, EVCON_WRITE_ERROR);
				return;
			}
		}

		/* we do have data to send */
		if (splice_length(&evcon->splice) > 0) {
			int n;

			n = splice_writer(&evcon->splice, fd);
			if (n > 0)
				evcon->content_sent += n;
			if (n == -1 &&
			    (errno != EINTR && errno != EAGAIN)) {
				logx(LOG_DEBUG, "IN_CONTENT, server write error: %m\n");
				evp_server_close(evcon, fd, EVCON_WRITE_ERROR);
				return;
			}
		}
		if (splice_length(&evcon->splice) > 0) {
			/*
			 * more data to send, schedule a write event
			 */
			evp_set_fwd_client2server(evcon, fd, PROXY_WRITE_TIMEOUT);
		} else {
			/*
			 * we have forwarded all data if:
			 *  1. the content buffer is empty and
			 *  2. the read side tells us there is no more data
			 */
			if (evcon->read_done) {
				evp_clear_fwd(evcon);

				evcon->direction = SERVER2CLIENT;
				evp_clear_req_state(evcon);
				/*
				 * start reading from server
				 */
				evp_set_read(evcon, evcon->server_fd, PROXY_READ_TIMEOUT);
			}
		}
		break;
#else
		if (evpbuffer_length(evcon->buffer) > 0) {
			int n;

			n = evpbuffer_write(evcon->buffer, fd);
			if (n > 0)
				evcon->content_sent += n;
			if (n == -1 &&
			    (errno != EINTR && errno != EAGAIN)) {
				logx(LOG_DEBUG, "IN_CONTENT, server write error: %m\n");
				evp_server_close(evcon, fd, EVCON_WRITE_ERROR);
				return;
			}
		}
		if (evpbuffer_length(evcon->buffer) > 0) {
			/*
			 * more data to send, schedule a write event
			 */
			evp_set_fwd_client2server(evcon, fd, PROXY_WRITE_TIMEOUT);
		} else {
			/*
			 * we have forwarded all data if:
			 *  1. the content buffer is empty and
			 *  2. the read side tells us there is no more data
			 */
			if (evcon->read_done) {
				evp_clear_fwd(evcon);

				evcon->direction = SERVER2CLIENT;
				evp_clear_req_state(evcon);
				/*
				 * start reading from server
				 */
				evp_set_read(evcon, evcon->server_fd, PROXY_READ_TIMEOUT);
			}
		}
		break;
#endif
	}
}

/*
 * server2client forward handling
 */

static void
evp_set_fwd_server2client(struct evproxy_connection *evcon, int fd, int timeout)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

        if (event_pending(&evcon->write_ev, EV_WRITE | EV_TIMEOUT, NULL))
		event_del(&evcon->write_ev);

	event_set(&evcon->write_ev, fd, EV_WRITE, evp_fwd_server2client_event, evcon);
	evproxy_add_event(&evcon->write_ev, timeout, PROXY_WRITE_TIMEOUT);
}

/*
 * append content
 */
static void evp_fwd_insert_content(struct evproxy_connection *evcon)
{
	size_t plen, n;

	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

	if (!evcon->insert_content || !evcon->insert_content_length)
		return;

	plen = evpbuffer_space(evcon->buffer);
	if (plen == 0)
		return;

	n = evpbuffer_cat(evcon->buffer, evcon->insert_content, evcon->insert_content_length);
	evcon->insert_content += n;
	evcon->insert_content_length -= n;
}

static void evp_fwd_server2client_event(int fd, short what, void *arg)
{
	struct evproxy_connection *evcon = arg;

	logx(LOG_DEBUG, "[#%ld] %s [%d]: %d\n", evcon->request_id, __func__, fd, what);

	if (what == EV_TIMEOUT) {
		logx(LOG_DEBUG, "client write timeout\n");
		evp_client_close(evcon, fd, EVCON_WRITE_TIMEOUT);
		return;
	}

	switch (evcon->write_state) {
	case IN_HEADERS: {
		int r;

		do {
			/* NOTE: write() can fail with EAGAIN, but then evpbuffer_length() 
			 *       will be non zero and the do loop will exit, scheduling
			 *       a new write request
			 */
			r = evp_server_send_headers(evcon, evcon->headers);
			if (evpbuffer_length(evcon->headers) > 0)
				if (evpbuffer_write(evcon->headers, fd) == -1 &&
				    (errno != EINTR && errno != EAGAIN)) {
					logx(LOG_DEBUG, "IN_HEADERS, client write error: %m\n");
					evp_client_close(evcon, fd, EVCON_WRITE_ERROR);
					return;
				}
		} while (r != WRITE_DONE && evpbuffer_length(evcon->headers) == 0);

		if (evpbuffer_length(evcon->headers) > 0) {
			/*
			 * more data to send, schedule a write event
			 */
			evp_set_fwd_server2client(evcon, fd, PROXY_WRITE_TIMEOUT);
			break;
		}
		evcon->write_state = IN_CONTENT;
		/* FALL THROUGH */
	}
	case IN_CONTENT:
#if USE_SPLICE
		if (evpbuffer_length(evcon->buffer) > 0) {
			int n;

			/* FIXME: this basicly assumes that we can vmsplice all data in one go */
			n = evpbuffer_vmsplice(evcon->buffer, &evcon->splice);
			if (n == -1 &&
			    (errno != EINTR && errno != EAGAIN)) {
				logx(LOG_DEBUG, "IN_CONTENT, client write error: %m\n");
				evp_client_close(evcon, fd, EVCON_WRITE_ERROR);
				return;
			}
		}

		while (splice_length(&evcon->splice) > 0) {
			int n;
			
#if 0	/* TODO: not yet supported */
			if (evcon->read_done)
				/*
				 * all data has been read, try to add the insertion content,
				 */
				evp_fwd_insert_content(evcon);
#endif

			n = splice_writer(&evcon->splice, fd);
			if (n > 0)
				evcon->content_sent += n;
			if (n == -1 &&
			    (errno != EINTR && errno != EAGAIN)) {
				logx(LOG_DEBUG, "IN_CONTENT, client write error: %m\n");
				evp_client_close(evcon, fd, EVCON_WRITE_ERROR);
				return;
			}

			if (splice_length(&evcon->splice) > 0) {
				/*
				 * more data to send, schedule a write event
				 */
				evp_set_fwd_server2client(evcon, fd, PROXY_WRITE_TIMEOUT);
				if (evcon->read_pending)
					evp_read_event(evcon->server_fd, -1, arg);

				logx(LOG_DEBUG, "[#%ld] %s [%d] more data to send\n", evcon->request_id, __func__, fd);
				return;
			}
			else if (evcon->read_done) {
				/*
				 * we have forwarded all data if:
				 *  1. the content buffer is empty and
				 *  2. the read side tells us there is no more data
				 */
				

#if 0	/* TODO: not yet supported */
				/* content insertion, if any */
				if (evcon->insert_content && evcon->insert_content_length)
					/*
					 * got more stuff to insert
					 */
					evp_fwd_insert_content(evcon);
#endif
			}
		}
#else
		while (evpbuffer_length(evcon->buffer) > 0) {
			int n;
			
			if (evcon->read_done)
				/*
				 * all data has been read, try to add the insertion content,
				 */
				evp_fwd_insert_content(evcon);

			n = evpbuffer_write(evcon->buffer, fd);
			if (n > 0)
				evcon->content_sent += n;
			if (n == -1 &&
			    (errno != EINTR && errno != EAGAIN)) {
				logx(LOG_DEBUG, "IN_CONTENT, client write error: %m\n");
				evp_client_close(evcon, fd, EVCON_WRITE_ERROR);
				return;
			}

			if (evpbuffer_length(evcon->buffer) > 0) {
				/*
				 * more data to send, shedule a write event
				 */
				evp_set_fwd_server2client(evcon, fd, PROXY_WRITE_TIMEOUT);
				if (evcon->read_pending && evpbuffer_space(evcon->buffer) != 0) {
					evpbuffer_normalize(evcon->buffer);
					evp_read_event(evcon->server_fd, -1, arg);
				}
				logx(LOG_DEBUG, "[#%ld] %s [%d] more data to send\n", evcon->request_id, __func__, fd);
				return;
			}
			else if (evcon->read_done) {
				/*
				 * we have forwarded all data if:
				 *  1. the content buffer is empty and
				 *  2. the read side tells us there is no more data
				 */
				
				/* content insertion, if any */
				if (evcon->insert_content && evcon->insert_content_length)
					/*
					 * got more stuff to insert
					 */
					evp_fwd_insert_content(evcon);
			}
		}
#endif

		/*
		 * all data has been forwarded
		 */
		logx(LOG_DEBUG, "[#%ld] %s [%d] read_done: %d, sent: %lld, clen: %lld\n",
		     evcon->request_id, __func__, fd, evcon->read_done, evcon->content_sent, evcon->out_content_length);
		if (evcon->read_done) {

			logx(LOG_DEBUG, "[#%ld] %s request done in %llu\n",
			     evcon->request_id, __func__, ltime() - evcon->reqstart);

			evp_clear_fwd(evcon);
			
			if (evcon->close_pending || !evcon->keep_alive) {
				/* close client connection */
				evp_client_close(evcon, evcon->client_fd, -1);
			} else {
				/* reset connection for next request */
				evcon->direction = CLIENT2SERVER;
				evp_clear_req_state(evcon);

				/*
				 * start reading from client
				 *
				 * TODO: connection semmantics
				 */
				evp_set_read(evcon, evcon->client_fd, PROXY_READ_TIMEOUT);
			}
		} 
		/*
		 * more data to read?
		 */
		else if (evcon->read_pending)
			evp_read_event(evcon->server_fd, -1, arg);

		break;
	}
}

/*
 * read handling
 */

/*
 * client part
 */

static void evp_client_read_header_req(struct evproxy_connection *evcon, int fd, int n)
{
	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

	switch (evproxy_process_req_header(evcon, evcon->buffer)) {
	case EVP_ERROR:
		evp_close_on_read(evcon, fd, EVCON_PROXY_INVALID_HEADER);
		break;

	case EVP_OK: {
		int plen;

		evcon->reqstart = ltime();
		plen = evpbuffer_length(evcon->buffer);
		if (plen != 0) {
			/*
			 * there is payload content pending
			 */
			evpbuffer_normalize(evcon->buffer);
		}
		evcon->content_read = plen;

		if (evcon->in_content_length > 0 && plen < evcon->in_content_length) {
			/*
			 * there is (might be) more data to be read from client
			 */
			/* FIXME: what about chunked transfer? */
			logx(LOG_DEBUG, "[#%ld] %s: setting client_read\n", evcon->request_id, __func__);
			evcon->read_state = IN_CONTENT;
			evp_set_read(evcon, fd, PROXY_READ_TIMEOUT);
		} else {
			/* TODO: deal with chunked encoding */
			evcon->read_done = 1;

			/* switch direction */
			evp_clear_read(evcon);
		}

		evproxy_check_connect(evcon);

		break;
	}

	case EVP_RETRY:
		/* there is (might be) more data to be read from client */
		logx(LOG_DEBUG, "[#%ld] %s: (re)arm client read event\n", evcon->request_id, __func__);
		evp_set_read(evcon, fd, PROXY_READ_TIMEOUT);
		break;
	}
}

static void evp_client_read_content_req(struct evproxy_connection *evcon, int fd, int n)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

	evcon->content_read += n;
	if (evcon->in_content_length >= 0 && evcon->in_content_length == evcon->content_read) {
		/*
		 * we have HTTP/1.1 Content-Lenght an we got all data
		 */
		evcon->read_done = 1;

		evp_clear_read(evcon);
	} else {
		/*
		 * more to come - schedule next read event
		 */
		evp_set_read(evcon, fd, PROXY_READ_TIMEOUT);
	}

#if USE_SPLICE
	if (splice_length(&evcon->splice) > 0)
		evp_fwd_client2server_event(evcon->server_fd, EV_WRITE, evcon);
#else
	if (evpbuffer_length(evcon->buffer) > 0)
		evp_fwd_client2server_event(evcon->server_fd, EV_WRITE, evcon);
#endif
}

static void evp_client_read_req(struct evproxy_connection *evcon, int fd, int n)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

	switch (evcon->read_state) {
	case IN_HEADERS:
		evp_client_read_header_req(evcon, fd, n);
		break;

	case IN_CONTENT:
		evp_client_read_content_req(evcon, fd, n);
		break;
	}
}

/*
 * server part
 */

static int is_whitelisted(const char *h)
{
	return 0;
}

static void evp_server_read_header_req(struct evproxy_connection *evcon, int fd, int len)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

	switch (evproxy_process_reply_header(evcon, evcon->buffer)) {
	case EVP_ERROR:
		logx(LOG_DEBUG, "[#%ld] %s [%d], header error\n", evcon->request_id, __func__, fd);
		evp_gateway_error(evcon, fd, -1, 502);
		break;

	case EVP_OK: {
		int plen;

		evp_log_request(evcon, E_ACCEPT);

		if (evcon->content_type && strncasecmp(evcon->content_type, "text/html", 9) == 0 &&
		    evcon->client->sep < INSERTIONS &&
		    !is_whitelisted(evcon->host)) {
			evcon->insert_content_length = insertions[evcon->client->sep].len;
			evcon->insert_content = insertions[evcon->client->sep].content;
			if (evcon->out_content_length >= 0) {
				evcon->out_content_length += evcon->insert_content_length;
				sprintf(evcon->content_length_header->value, "%lld", evcon->out_content_length);
			}
		}

		plen = evpbuffer_length(evcon->buffer);
		if (plen != 0) {
			/*
			 * there is payload content pending
			 */
			evpbuffer_normalize(evcon->buffer);
		}
		evcon->content_read = plen;

		if ((evcon->in_content_length < 0) ||
		    (evcon->in_content_length > 0 && plen < evcon->in_content_length)) {
			/* there is (might be) more data to be read from client
			 * 
			 * either no Content-Length header (HTTP/1.0 or 0.9) or more data
			 */
			logx(LOG_DEBUG, "[#%ld] %s: setting server_read (need %lld bytes\n", evcon->request_id, __func__, evcon->in_content_length - plen);
			evcon->read_state = IN_CONTENT;
			evp_set_read(evcon, fd, PROXY_READ_TIMEOUT);
		} else {
			/* TODO: deal with chunked encoding */
			evcon->read_done = 1;

			/* switch direction */
			evp_clear_read(evcon);
		}

		/*
		 * prepare response headers and send them
		 */
		evp_exec_fwd_server2client_event(evcon->client_fd, evcon);

		break;
	}

	case EVP_RETRY:
		/* there is (might be) more data to be read from server */
		logx(LOG_DEBUG, "[#%ld] %s: (re)arm client read event\n", evcon->request_id, __func__);
		evp_set_read(evcon, fd, PROXY_READ_TIMEOUT);
		break;
	}
}

static void evp_server_read_content_req(struct evproxy_connection *evcon, int fd, int n)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

	evcon->content_read += n;
	logx(LOG_DEBUG, "[#%ld] %s [%d], want: %lld, got: %lld\n", evcon->request_id, __func__, fd, evcon->in_content_length, evcon->content_read);

	if (evcon->in_content_length >= 0 && evcon->in_content_length == evcon->content_read) {
		/*
		 * we have HTTP/1.1 Content-Lenght an we got all data
		 */
		logx(LOG_DEBUG, "[#%ld] %s [%d] read_done: %d\n", evcon->request_id, __func__, fd, evcon->read_done);
		evcon->read_done = 1;

		evp_clear_read(evcon);
	} else {
		/*
		 * more to come - schedule next read event
		 */
		evp_set_read(evcon, fd, PROXY_READ_TIMEOUT);
	}

#if USE_SPLICE
	if (splice_length(&evcon->splice) > 0)
		evp_exec_fwd_server2client_event(evcon->client_fd, evcon);
#else
	if (evpbuffer_length(evcon->buffer) > 0)
		evp_exec_fwd_server2client_event(evcon->client_fd, evcon);
#endif
}

static void evp_server_read_req(struct evproxy_connection *evcon, int fd, int n)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]: %d\n", evcon->request_id, __func__, fd, n);

	switch (evcon->read_state) {
	case IN_HEADERS:
		evp_server_read_header_req(evcon, fd, n);
		break;

	case IN_CONTENT:
		evp_server_read_content_req(evcon, fd, n);
		break;
	}
}

/*
 * generic read switch
 */
static void evp_read_event_switch(struct evproxy_connection *evcon, int fd, int n)
{
	switch (evcon->direction) {
	case CLIENT2SERVER:
		evp_client_read_req(evcon, fd, n);
		break;

	case SERVER2CLIENT:
		evp_server_read_req(evcon, fd, n);
		break;
	}
}

static void evp_read_event(int fd, short what, void *arg)
{
	struct evproxy_connection *evcon = arg;
	ssize_t n;

	logx(LOG_DEBUG, "[#%ld] %s [%d]: %d\n", evcon->request_id, __func__, fd, what);

	if (what == EV_TIMEOUT) {
		logx(LOG_DEBUG, "read timeout on fd: %d\n", fd);
		evp_close_on_read(evcon, fd, EVCON_READ_TIMEOUT);
		return;
	}

	evcon->read_pending = 0;

#if USE_SPLICE
	if (evcon->read_state == IN_CONTENT) {
		ssize_t len = evcon->in_content_length;

		if (len >= 0)
			len -= evcon->content_read;
		n = splice_reader(&evcon->splice, fd, len);
	} else
		n = evpbuffer_read(evcon->buffer, fd);
#else
	n = evpbuffer_read(evcon->buffer, fd);
#endif
	logx(LOG_DEBUG, "[#%ld] %s [%d]: res: %zd\n", evcon->request_id, __func__, fd, n);
	if (n > 0) {
		logx(LOG_DEBUG, "[#%ld] %s: read %d, %zd bytes\n", evcon->request_id, __func__, fd, n);
		evp_read_event_switch(evcon, fd, n);
	} else if (n == -2) {
		logx(LOG_DEBUG, "[#%ld] %s: read pending %d\n", evcon->request_id, __func__, fd);
		evcon->read_pending = 1;
	} else if (n == -1 && errno != EWOULDBLOCK) {
		logx(LOG_DEBUG, "[#%ld] %s: bad read on %d, errno: %d\n", evcon->request_id, __func__, fd, errno);
		evp_close_on_read(evcon, fd, EVCON_READ_ERROR);
	} else if (n == 0) {
		logx(LOG_DEBUG, "[#%ld] %s: eof on %d\n", evcon->request_id, __func__, fd);
		evp_close_on_read(evcon, fd, EVCON_READ_EOF);
	}
}

static void evp_set_read(struct evproxy_connection *evcon, int fd, int timeout)
{
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

        if (event_pending(&evcon->read_ev, EV_READ | EV_TIMEOUT, NULL))
		event_del(&evcon->read_ev);

	event_set(&evcon->read_ev, fd, EV_READ, evp_read_event, evcon);
	evproxy_add_event(&evcon->read_ev, timeout, PROXY_READ_TIMEOUT);
}

static void evp_clear_read(struct evproxy_connection *evcon)
{
	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

        if (event_pending(&evcon->read_ev, EV_READ | EV_TIMEOUT, NULL))
		event_del(&evcon->read_ev);
}

//#define EVP_CONNECT_READY  (EVP_REQUEST_READ | EVP_HOST_RESOLVED | EVP_CLIENT_INFO)
#define EVP_CONNECT_READY  (EVP_REQUEST_READ | EVP_CLIENT_INFO)


static void do_redir(struct evproxy_connection *evcon, const char *url)
{
	static char newlocation[4096];

	urlizer(newlocation, sizeof(newlocation), url, evcon);

	evpbuffer_clear(evcon->headers);
	evpbuffer_clear(evcon->buffer);
	evpbuffer_printf(evcon->buffer, 
			 "HTTP/1.0 302 Found" CRLF
			 "Location: %s" CRLF
			 "Content-Type: text/html" CRLF
			 "Connection: close" CRLF
			 "Cache-Control: private, no-cache, must-revalidate" CRLF
			 "Expires: Mon, 26 Jul 1997 05:00:00 GMT" CRLF
			 "Pragma: no-cache" CRLF
			 "" CRLF
			 "<HTML>",
			 newlocation);

	struct zone *zn = get_zone(scg_mark_zone(evcon->mark));
	if (zn && zn->wispr_nexturl) {
		static char nexturl[4096];

		urlizer(nexturl, sizeof(nexturl), zn->wispr_nexturl, evcon);
		evpbuffer_printf(evcon->buffer, 
				 "<!--\n"
				 "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
				 "<WISPAccessGatewayParam"
				 " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
				 " xsi:noNamespaceSchemaLocation=\"http://www.acmewisp.com/WISPAccessGatewayParam.xsd\">"
				 "<Proxy>"
				 "<MessageType>110</MessageType>"
				 "<ResponseCode>200</ResponseCode>"
				 "<NextURL>%s</NextURL>"
				 "</Proxy>"
				 "</WISPAccessGatewayParam>\n"
				 "-->",
				 nexturl);
	}

	evpbuffer_printf(evcon->buffer, 
			 "\n<head><meta http-equiv=\"refresh\" content=\"0; URL=%s\"><title>Redirection</title>"
			 "</head><body>Please <a href='%s'>click here</a> to continue</body>\n</HTML>",
			 newlocation, newlocation);

	evcon->in_content_length = evcon->out_content_length = evcon->insert_content_length = -1;
	evcon->content_length_header = NULL;
	evcon->insert_content = NULL;

	evcon->direction = SERVER2CLIENT;
	evcon->write_state = IN_CONTENT;

	evcon->close_pending = 1;
	evp_exec_fwd_server2client_event(evcon->client_fd, evcon);
}

static int evproxy_process_ac(struct evproxy_connection *evcon, struct ac *ac, struct acl **acl)
{
	struct acl_entry *n;

	/* scan all ACL's */
	SIMPLEQ_FOREACH(n, &ac->acl_list, acl_list)
	{
		int policy = n->entry->defaultpolicy;

		logx(LOG_DEBUG, "Testing: %s, Policy: %d, Default: %d\n", n->entry->aclid, n->entry->policy, n->entry->defaultpolicy);

		if (n->entry->uris_matches &&
		    is_site(n->entry, 1, evcon->host, evcon->port, evcon->uri))
			policy = n->entry->policy;

		if (policy != E_IGNORE) {
			*acl = n->entry;
			return policy;
		}
	}

	*acl = NULL;
	return E_IGNORE;
}

static void evproxy_check_connect(struct evproxy_connection *evcon)
{
	struct acl *acl;
	struct zone *zone;
	struct ac *ac;
        struct sockaddr_in sin;
        struct linger linger;
        int on = 1;
	int verdict = E_DENY;
	int r;

	if ((evcon->flags & EVP_CONNECT_READY) != EVP_CONNECT_READY)
		return;

	zone = get_zone(scg_mark_zone(evcon->mark));
	logx(LOG_DEBUG, "got Zone: %d %p (%s)\n", scg_mark_zone(evcon->mark), zone, zone ? zone->zoneid : "(NULL)");
	ac = get_ac(zone, scg_mark_accessclass(evcon->mark));
	logx(LOG_DEBUG, "got AC: %d %p (%s)\n", scg_mark_accessclass(evcon->mark), ac, ac ? ac->acid : "(NULL)");
	acl = get_acl(scg_mark_acl(evcon->mark));
	logx(LOG_DEBUG, "got ACL: %d %p (%s)\n", scg_mark_acl(evcon->mark), acl, acl ? acl->aclid : "(NULL)");

	if (acl && acl->defaultpolicy == E_IGNORE && !acl->uris_matches) {
		/* a ACL match with defaultpolicy == IGNORE and no URIs means we hit an IP policy */
		verdict = acl->policy;
	} else if (ac) {
		verdict = evproxy_process_ac(evcon, ac, &acl);
		logx(LOG_DEBUG, "AC Verdict: %d\n", verdict);
	} else
		verdict = E_DENY;

	if (!evcon->client || evcon->client->validation == CLNT_UNKNOWN)
		verdict = E_REDIRECT;

	if (verdict == E_DENY || verdict == E_REDIRECT) {
		if (!acl || !acl->url) {
			logx(LOG_ERR, "redir requested but no redir URL (ACL: %s)\n", acl ? acl->aclid : "(NULL)");
			evp_gateway_error(evcon, -1, EVCON_CONNECT_ERROR, 500);
		} else {
			evcon->result = 302;
			evp_log_request(evcon, verdict);

			do_redir(evcon, acl->url);
		}
		return;
	}

	if (evcon->server_fd > 0) {
		evp_fwd_client2server_event(evcon->server_fd, EV_WRITE, evcon);
		return;
	}

	evcon->connected = 0;

	if ((evcon->server_fd = inet_socket(evcon->netns)) < 0) {
		logx(LOG_ERR, "failed to get socket: %m\n");
		evp_gateway_error(evcon, -1, EVCON_CONNECT_ERROR, 504);
		return;
	}

        if (fcntl(evcon->server_fd, F_SETFL, O_NONBLOCK) == -1) {
                logx(LOG_ERR, "fcntl(O_NONBLOCK): %m\n");
		evp_gateway_error(evcon, -1, EVCON_CONNECT_ERROR, 504);
		return;
        }

        setsockopt(evcon->server_fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on));
        setsockopt(evcon->server_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
        linger.l_onoff = 0;
        linger.l_linger = 5;
	setsockopt(evcon->server_fd, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));
        setsockopt(evcon->server_fd, SOL_IP, IP_TRANSPARENT, (void *)&on, sizeof(on));

	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr = evcon->remote_addr;
	if (bind(evcon->server_fd, &sin, sizeof(sin)) == -1) {
		logx(LOG_DEBUG, "[#%ld] %s: TPROXY bind failed, errno: %d (%s)\n",
		     evcon->request_id, __func__, errno, strerror(errno));
	}

        sin.sin_family = AF_INET;
        sin.sin_port   = htons(evcon->port);
	sin.sin_addr   = evcon->host_addr;
	r = connect(evcon->server_fd, &sin, sizeof(sin));

	logx(LOG_DEBUG, "[#%ld] %s: connecting on fd %d to host: '%s', rc: %d, errno: %d (%s)\n",
	     evcon->request_id, __func__, evcon->server_fd, evcon->host, r, errno, strerror(errno));

	if (r == -1 && errno == EINPROGRESS) {
		socklen_t addrlen = sizeof(sin);

		r = getsockname(evcon->server_fd, &sin, &addrlen);
		if (r < 0)
			logx(LOG_DEBUG, "[#%ld] %s: sockname res: %d, %m\n", evcon->request_id, __func__, r);
		else
			logx(LOG_DEBUG, "[#%ld] %s: sockname port: %d\n", evcon->request_id, __func__, ntohs(sin.sin_port));

		logx(LOG_DEBUG, "[#%ld] %s: adding connect event\n", evcon->request_id, __func__);
		evp_set_connect(evcon, evcon->server_fd, PROXY_CONNECT_TIMEOUT);
	}
}

#if 0
static void evp_host_resolve(int result, char type, int count, int ttl, void *addresses, void *arg)
{
	struct evproxy_connection *evcon = arg;

	logx(LOG_DEBUG, "got dns: result: %d, type: %d, count: %d, ttl: %d\n", result, type, count, ttl);

	if (result != 0) {
		evp_server_close(evcon, -1, EVCON_CONNECT_ERROR);
		return;
	}

	if (type == DNS_PTR) {
		logx(LOG_DEBUG, "ptr: %s\n", (char *)addresses);
		return;
	}
	
	evcon->host_addr = *(struct in_addr *)addresses;
	evcon->flags |= EVP_HOST_RESOLVED;

	logx(LOG_DEBUG, "IP: %s\n", inet_ntoa(*(struct in_addr *)addresses));

	evproxy_check_connect(evcon);
}
#endif

/*
*/

#if defined(WORDS_BIGENDIAN)
#define HTTP_INT_lc ('h' << 24 | 't' << 16 | 't' << 8 | 'p')
#define HTTP_INT_uc ('H' << 24 | 'T' << 16 | 'T' << 8 | 'P')
#else
#define HTTP_INT_lc ('h' | 't' << 8 | 't' << 16 | 'p' << 24)
#define HTTP_INT_uc ('H' | 'T' << 8 | 'T' << 16 | 'P' << 24)
#endif

static int parser_header(struct evproxy_connection *evcon, struct evpbuffer *p,
			 int (*cb)(char *, size_t, struct evproxy_connection *))
{
	while (42) {
		uint8_t *buf, *next;
		size_t len;
		ssize_t l;

		/* buffer start might have changed */
		buf = evpbuffer_buffer(p);
		len = evpbuffer_length(p);

		next = memchr(buf, '\n', len);
		if (!next) {
			evpbuffer_normalize(p);

			logx(LOG_DEBUG, "[#%ld] %s, RETRY\n", evcon->request_id, __func__);
			return EVP_RETRY;
		}

		l = next - buf;
		next++;

		if (l > 0 && buf[l - 1] == '\r')
			l--;

		cb((char *)buf, l, evcon);

		evpbuffer_pull(p, next - buf);

		if (l == 0) {
			logx(LOG_DEBUG, "[#%ld] %s, Empty Line....\n", evcon->request_id, __func__);
			return EVP_OK;
		}

		logx(LOG_DEBUG, "[#%ld] %s, header: %zd, -%.*s-\n", evcon->request_id, __func__, l, (int)l, buf);
	}
	return EVP_RETRY;
}

static int evproxy_process_reply_header_cb(char *line, size_t len, struct evproxy_connection *evcon)
{
	struct header_line *hline;

	if (!len)
		return 0;

	hline = headers_append(evcon->reply_headers, line, len);

	if (strncasecmp(line, "Content-Type: ", 14) == 0) {
		evcon->content_type = talloc_strndup(evcon, line + 14, len - 14);
	} else if (strncasecmp(line, "Content-Length: ", 16) == 0) {
		evcon->in_content_length = evcon->out_content_length = strtoll(line + 16, NULL, 0);
		evcon->content_length_header = hline;
	} else if (strncasecmp(line, "Connection: ", 12) == 0) {
		evcon->keep_alive = strncasecmp(line + 12, "close", 5) != 0;
	} else if (strncasecmp(line, "Transfer-Encoding: ", 19) == 0) {
		evcon->chunked = strncasecmp(line + 19, "chunked", 7) != 0;
	}

	return 0;
}

/* FIXME: the in_/out_ lenght stuff is wrong */
static int evproxy_process_chunk_header(struct evproxy_connection *evcon, struct evpbuffer *p)
{
	char *buf, *h;

	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

	buf = (char *)evpbuffer_buffer(p);

	h = memchr(buf, '\n', evpbuffer_length(p));
	if (!h)
		return EVP_RETRY;

	evcon->in_content_length = strtoll(buf, NULL, 16);
	evcon->in_content_length += h - buf + 1 + 2;
	evcon->out_content_length = evcon->in_content_length;

	logx(LOG_DEBUG, "[#%ld] %s: length: %lld\n", evcon->request_id, __func__, evcon->in_content_length);

	return EVP_OK;
}

static int evproxy_process_reply_header(struct evproxy_connection *evcon, struct evpbuffer *p)
{
	char *buf, *h, *c;
	int r;

	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);
	logx(LOG_DEBUG, "req: -%.*s-\n", (int)(evpbuffer_length(p) > 128 ? 128 : evpbuffer_length(p)), evpbuffer_buffer(p));

	buf = (char *)evpbuffer_buffer(p);

	if (*(uint32_t *)buf != HTTP_INT_lc &&
	    *(uint32_t *)buf != HTTP_INT_uc) {
		logx(LOG_DEBUG, "%s: http reply error: %x != %x\n", __func__, *(uint32_t *)buf, HTTP_INT_uc);
	
		return EVP_ERROR;
	}

	h = memchr(buf, '\n', evpbuffer_length(p));
	if (!h)
		return EVP_RETRY;
	*h = '\0';
	if (h > buf && *(h - 1) == '\r')
		*(h - 1) = '\0';

	c = memchr(buf, ' ', h - buf);
	if (!c)
		return EVP_ERROR;

	errno = 0;
	evcon->result = strtol(c, NULL, 10);
	if (errno != 0)
		return EVP_ERROR;

	evcon->reply = talloc_strdup(evcon, buf);
	evpbuffer_pull(p, h - buf + 1);

	switch (evcon->result) {
	case 100 ... 199:
	case 204:
	case 304:
		/* reply's without a body */
		evcon->in_content_length = 0;

		/* no Content-Length allowed */
		if (evcon->content_length_header)
			logx(LOG_ERR, "%s: http reply %d with Content-Length header\n", __func__, evcon->result);
		break;
	}
	r = parser_header(evcon, p, evproxy_process_reply_header_cb);

	if (r != EVP_OK)
		return r;

	if (evcon->chunked)
		r = evproxy_process_chunk_header(evcon, p);

	return r;
}

static int evproxy_process_req_header_cb(char *line, size_t len, struct evproxy_connection *evcon)
{
	if (len == 0) {
		evcon->last_header = line;
	} else if (strncasecmp(line, "X-SCG-", 6) == 0) {
		return 0;
	} else if (strncasecmp(line, "Host: ", 6) == 0) {
		evcon->host = talloc_strndup(evcon, line + 6, len - 6);
	} else if (strncasecmp(line, "Connection: ", 12) == 0) {
		evcon->keep_alive = strncasecmp(line + 12, "close", 5) != 0;
	} else if (strncasecmp(line, "Content-Length: ", 16) == 0) {
		evcon->out_content_length = evcon->in_content_length = strtol(line + 16, NULL, 0);
	} else if (strncasecmp(line, "User-Agent: ", 12) == 0) {
		evcon->user_agent = talloc_strndup(evcon, line + 12, len - 12);
	} else if (strncasecmp(line, "Referer: ", 9) == 0) {
		evcon->referer = talloc_strndup(evcon, line + 9, len - 9);
	} else if (strncasecmp(line, "Accept-Encoding: ", 17) == 0) {
		/* remove Accept-Enconding from requests to avoid compressed answers */
		return 0;
	}

	headers_append(evcon->request_headers, line, len);

	return 0;
}

static int evproxy_process_req_header(struct evproxy_connection *evcon, struct evpbuffer *p)
{
	char *buf;
	int r;

	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);
	
	if (!evcon->request) {
		char *uri, *end, *h;

		buf = (char *)evpbuffer_buffer(p);

		h = memchr(buf, '\n', evpbuffer_length(p));
		if (!h)
			return EVP_RETRY;
		
		*h = '\0';
		if (h > buf && *(h - 1) == '\r')
			*(h - 1) = '\0';
		
		uri = strchr(buf, ' ');
		if (!uri)
			return EVP_ERROR;
		*uri++ = '\0';
		
		end = strchr(uri, ' ');
		if (!end)
			return EVP_ERROR;
		*end++ = '\0';
		
		logx(LOG_DEBUG, "uri: -%s-, end: -%s-\n", uri, end);
		
		/* figure out the request type */
		if (buf[0] == 'C' && buf[1] == 'O' &&
		    buf[2] == 'N' && buf[3] == 'N' &&
		    buf[4] == 'E' && buf[5] == 'C' &&
		    buf[6] == 'T' && buf[7] == ' ')
			
			evcon->connect = 1;
		
		if (*(uint32_t *)uri == HTTP_INT_lc ||
		    *(uint32_t *)uri == HTTP_INT_uc) {
			char *e;
			
			/* proxy request */
			logx(LOG_DEBUG, "proxy request\n");
			
			uri += 4;
			evcon->ssl = (*uri == 's' || *uri == 'S');
			if (evcon->ssl) {
				if (!evcon->connect)
					return EVP_ERROR;
				uri++;
			}
			
			if (uri[0] != ':' || uri[1] != '/' || uri[2] != '/')
				return EVP_ERROR;
			uri += 3;
			e = strchr(uri, '/');
			if (!e)
				return EVP_ERROR;
			
			evcon->host = talloc_strndup(evcon, uri, e - uri);
			if (!evcon->host)
				return EVP_ERROR;
/*
			evdns_resolve_ipv4(evcon->host, 0, evp_host_resolve, evcon);
*/		
			uri = e;
		}
		
		if (!end[0] == 'H' || !end[1] == 'T' ||
		    !end[2] == 'T' || !end[3] == 'P' ||
		    !end[4] == '/' || !isdigit(end[5]) ||
		    !end[6] == '.' || !isdigit(end[7]))
			return EVP_ERROR;
		
		evcon->major = end[5] - '0';
		evcon->minor = end[7] - '0';
		
		logx(LOG_DEBUG, "major: %d, minor: %d\n", evcon->major, evcon->minor);
		
		// evcon->request = talloc_asprintf(evcon, "%s %s HTTP/%d.%d", buf, uri, evcon->major, evcon->minor);
		evcon->request = talloc_asprintf(evcon, "%s %s HTTP/%d.%d", buf, uri, evcon->major, 0);
		if (!evcon->request)
			return EVP_ERROR;

		evcon->proto = talloc_strdup(evcon, buf);
		evcon->uri = talloc_strdup(evcon, uri);

		logx(LOG_DEBUG, "[#%ld] %s: %s\n", evcon->request_id, __func__, evcon->request);
		
		evpbuffer_pull(p, (h + 1) - buf);
	}

	r = parser_header(evcon, p, evproxy_process_req_header_cb);

	if (r != EVP_OK)
		return r;

	if (!evcon->host) {
		char ip[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET, &evcon->host_addr, ip, sizeof(ip));
		evcon->host = talloc_strndup(evcon, ip, sizeof(ip));
	}

	logx(LOG_DEBUG, "%s: #1: %zd, %zd, %zd\n", __func__, p->head, p->tail, p->size);
	logx(LOG_DEBUG, "Host: -%s-\n", evcon->host);

	evcon->flags |= EVP_REQUEST_READ;

	return EVP_OK;
}

void evp_get_client_cb(struct evproxy_connection *evcon)
{
	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

	evcon->flags |= EVP_CLIENT_INFO;

//	add_client_by_session_id(evcon->client);
	logx(LOG_DEBUG, "%s, session_id: %s, client: %p\n", __func__,  evcon->client->session_id, evcon->client);

	evproxy_check_connect(evcon);
}

static void evp_get_client(struct evproxy_connection *evcon)
{
	struct evp_client *client;

	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

	client = get_client_by_addr(evcon->remote_addr);
	logx(LOG_DEBUG, "[#%ld] %s: client: %p\n", evcon->request_id, __func__, client);
	if (!client) {
		client = talloc_zero(NULL, struct evp_client);
		if (!client)
			return;

		client->addr = evcon->remote_addr.s_addr;

		struct zone *zn = get_zone(scg_mark_zone(evcon->mark));
		if (zn)
			client->zone = zn->instance;

		add_client_by_addr(client);
		TAILQ_INIT(&client->connection_queue);
		logx(LOG_DEBUG, "%s: new client\n", __func__);

	} else
		logx(LOG_DEBUG, "%s: found existing client\n", __func__);

	evcon->client = talloc_reference(evcon, client);
	TAILQ_INSERT_TAIL(&client->connection_queue, evcon, connection_queue);
	logx(LOG_DEBUG, "[#%ld] %s pushing evcon %p onto client %p\n", evcon->request_id, __func__, evcon, client);

	switch (client->validation) {
	case CLNT_UNKNOWN:
		/* FIXME: handle comm failures */
		comm_get_client_info(client);
		break;

	case CLNT_VALIDATED:
		evcon->flags |= EVP_CLIENT_INFO;
		break;

	case CLNT_VALIDATION_PENDING:
		break;
	}

	client->ts = time(NULL);
}

/** construct requests headers
 *
 * take decoded request headers from evcon->request and build a compliant HTTP request in p
 */
static void evp_client_send_headers(struct evproxy_connection *evcon, struct evpbuffer *p)
{
	struct header_line *line;

	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

	/*
	 * is this the first call for this request?
	 *
	 *   evcon->request will be NULL for susequent invocations
	 */
	if (evcon->request) {
		/*
		 * put request line
		 */
		evpbuffer_printf(p, "%s" CRLF, evcon->request);
		talloc_free(evcon->request);
		evcon->request = NULL;

		/* init proxy information headers */
		if ((evcon->host_addr.s_addr & proxy_fwd_mask) == (proxy_fwd.s_addr & proxy_fwd_mask)) {
			char ip[INET6_ADDRSTRLEN];
			
			inet_ntop(AF_INET, &evcon->remote_addr, ip, INET_ADDRSTRLEN);

			headers_append_new(evcon->request_headers, "X-SCG-Session-Token", "%s", evcon->client->token);
			headers_append_new(evcon->request_headers, "X-SCG-Session-Id", "%s", evcon->client->session_id);
			headers_append_new(evcon->request_headers, "X-SCG-Session-Acct-Id", "%s", evcon->client->acct_session_id);

			struct zone *zn = get_zone(scg_mark_zone(evcon->mark));
			if (zn) {
				headers_append_new(evcon->request_headers, "X-SCG-Session-Zone-Id", "%s", zn->zoneid);

				struct ac *ac = get_ac(zn, scg_mark_accessclass(evcon->mark));
				if (ac)
					headers_append_new(evcon->request_headers, "X-SCG-Session-AccessClass-Id", "%s", ac->acid);
			}

			headers_append_new(evcon->request_headers, "X-SCG-Client-IP", "%s", ip);
			headers_append_new(evcon->request_headers, "X-SCG-Client-MAC", "%02x:%02x:%02x:%02x:%02x:%02x",
					   evcon->client->mac[0], evcon->client->mac[1], evcon->client->mac[2], 
					   evcon->client->mac[3], evcon->client->mac[4], evcon->client->mac[5]);
			if (evcon->client->uid)
				headers_append_new(evcon->request_headers, "X-SCG-UID", "%s", evcon->client->uid);

			if (evcon->client->remote_id)
				headers_append_new(evcon->request_headers, "X-SCG-Remote-Id", "%s", evcon->client->remote_id);
			if (evcon->client->circuit_id)
				headers_append_new(evcon->request_headers, "X-SCG-Circuit-Id", "%s", evcon->client->circuit_id);
			if (evcon->client->location_id)
				headers_append_new(evcon->request_headers, "X-SCG-Location-Id", "%s", evcon->client->location_id);

			//headers_append_new(evcon->request_headers, "X-SEP", "%d", evcon->client->sep);
		}
	}
	else if (SIMPLEQ_EMPTY(evcon->request_headers)) {
		/*
		 * no more headers to send
		 */
		return;
	}

	while (!SIMPLEQ_EMPTY(evcon->request_headers)) {
		/*
		 * add headers to buffer
		 */
		line = SIMPLEQ_FIRST(evcon->request_headers);
		
		if (evpbuffer_space(p) > line->len + 6) {
			evpbuffer_printf(p, "%s: %s" CRLF, line->header, line->value);
			logx(LOG_DEBUG, "[#%ld] %s: push to buffer: %zd, key: %s\n", evcon->request_id, __func__, evpbuffer_length(p), line->header);
		} else if (!evpbuffer_size(p) > line->len + 6) {
			logx(LOG_DEBUG, "[#%ld] %s: wait, need more space: %zd\n", evcon->request_id, __func__, evpbuffer_length(p));
			return;
		} else
			logx(LOG_DEBUG, "[#%ld] %s: header bigger that buffer: %d ... %zd ... %zd\n", evcon->request_id, __func__,
				line->len,
				evpbuffer_size(p),
				evpbuffer_space(p));
		
		SIMPLEQ_REMOVE_HEAD(evcon->request_headers, line, hlist);
		talloc_free(line);
	}

	if (evpbuffer_space(p) < 2)
		return;
	evpbuffer_printf(p, CRLF);
}

/** construct reply headers
 *
 * take decoded reply headers from evcon->reply and build a compliant HTTP reply in p
 */
static int evp_server_send_headers(struct evproxy_connection *evcon, struct evpbuffer *p)
{
	struct header_line *line;

	logx(LOG_DEBUG, "[#%ld] %s\n", evcon->request_id, __func__);

	/*
	 * is this the first call for this reply?
	 *
	 *   evcon->reply will be NULL for susequent invocations
	 */
	if (evcon->reply){
		/*
		 * 1st call
		 */
		evpbuffer_printf(p, "%s" CRLF, evcon->reply);
		talloc_free(evcon->reply);
		evcon->reply = NULL;
	}
	else if (SIMPLEQ_EMPTY(evcon->reply_headers)) {
		/*
		 * no more headers to send
		 */
		return WRITE_DONE;
	}

	while (!SIMPLEQ_EMPTY(evcon->reply_headers)) {
		/*
		 * add headers to buffer
		 */
		line = SIMPLEQ_FIRST(evcon->reply_headers);
		
		if (evpbuffer_space(p) > line->len + 6) {
			evpbuffer_printf(p, "%s: %s" CRLF, line->header, line->value);
			logx(LOG_DEBUG, "[#%ld] %s: push to buffer: %zd, key: %s\n", evcon->request_id, __func__, evpbuffer_length(p), line->header);
		} else if (!evpbuffer_size(p) > line->len + 6) {
			logx(LOG_DEBUG, "[#%ld] %s: wait, need more space: %zd\n", evcon->request_id, __func__, evpbuffer_length(p));
			return WRITE_NEED_MORE_SPACE;
		} else
			logx(LOG_DEBUG, "[#%ld] %s: header bigger that buffer: %d ... %zd ... %zd\n", evcon->request_id, __func__,
				line->len,
				evpbuffer_size(p),
				evpbuffer_space(p));
		
		SIMPLEQ_REMOVE_HEAD(evcon->reply_headers, line, hlist);
		talloc_free(line);
	}

	if (evpbuffer_space(p) < 2)
		return WRITE_NEED_MORE_SPACE;
	evpbuffer_printf(p, CRLF);
	return WRITE_DONE;
}

static void evproxy_get_request(struct evproxy *proxy, int fd,
				struct sockaddr *sa, socklen_t salen)
{
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];
	struct evproxy_connection *evcon;
	struct sockaddr_in dst;
	socklen_t dst_len = sizeof(dst);

	evcon = talloc(proxy, struct evproxy_connection);
	if (!evcon)
		return;

	memset(evcon, 0, sizeof(struct evproxy_connection));
	evcon->request_id = request_id++;
	logx(LOG_DEBUG, "[#%ld] %s [%d]\n", evcon->request_id, __func__, fd);

	evcon->direction = CLIENT2SERVER;
	evcon->read_state = IN_HEADERS;
	evcon->write_state = IN_HEADERS;

	evcon->netns = proxy->netns;
	evcon->client_fd = fd;
	evcon->server_fd = -1;
	evcon->remote_addr = ((struct sockaddr_in *)sa)->sin_addr;

	evcon->in_content_length = -1;
	evcon->out_content_length = -1;

        memset(&dst, 0, sizeof(dst));
	dst_len = sizeof(dst);
        if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &dst, &dst_len) == -1) {
		logx(LOG_ERR, "%s: SO_ORIGINAL_DST failed\n", __func__);
		close(fd);
		talloc_free(evcon);
		return;
	}

	inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &dst.sin_addr, dst_ip, sizeof(dst_ip));

	logx(LOG_DEBUG, "[#%ld] %s: proxy from %s:%d to %s:%d",
	     evcon->request_id, __func__,
	     src_ip, ntohs(((struct sockaddr_in *)sa)->sin_port),
	     dst_ip, ntohs(dst.sin_port));

	evcon->host_addr = dst.sin_addr;
	evcon->port = ntohs(dst.sin_port);

	dst_len = sizeof(evcon->mark);
        if (getsockopt(fd, SOL_IP, SO_CONNTRACK_MARK, &evcon->mark, &dst_len) == -1) {
		logx(LOG_WARNING, "%s: failed to get conntrack mark\n", __func__);

		/* TODO: fill in default mark */
		evcon->mark = scg_mark(1, 1, 1, 0);
	}
	logx(LOG_DEBUG, "[#%ld] %s: get_conntrack_mark, mark: %x (Zone: %d, AC: %d, ACL: %d, Session: %d)\n",
	     evcon->request_id, __func__, evcon->mark,
	     scg_mark_zone(evcon->mark), scg_mark_accessclass(evcon->mark), scg_mark_acl(evcon->mark), scg_mark_session(evcon->mark));

	evcon->request_headers = talloc(evcon, struct hlist);
	evcon->reply_headers = talloc(evcon, struct hlist);
	if (!evcon->request_headers || !evcon->reply_headers) {
		close(fd);
		talloc_free(evcon);
		return;
	}

#if USE_SPLICE
	if (splice_init(&evcon->splice) == -1) {
		logx(LOG_ERR, "[#%ld] %s [%d]: splice_init() failed (%m)\n", evcon->request_id, __func__, fd);
		close(fd);
		talloc_free(evcon);
		return;
	}
	logx(LOG_DEBUG, "[#%ld] %s [%d]: pipe read: %d, write: %d\n", evcon->request_id, __func__, fd,
	     evcon->splice.fdes[0], evcon->splice.fdes[1]);
#endif

	SIMPLEQ_INIT(evcon->request_headers);
	SIMPLEQ_INIT(evcon->reply_headers);

        /* Allocate request structure */
        if ((evcon->buffer = evpbuffer_new(evcon, proxy_buffer_size)) == NULL) {
                logx(LOG_ERR, "%s: evbuffer_new\n", __func__);
                goto error;
        }
        if ((evcon->headers = evpbuffer_new(evcon, proxy_buffer_size)) == NULL) {
                logx(LOG_ERR, "%s: evbuffer_new\n", __func__);
                goto error;
        }

	evp_get_client(evcon);
	evp_set_read(evcon, fd, PROXY_READ_TIMEOUT);

	return;

 error:
        if (evcon != NULL)
                evproxy_request_free(evcon);
}

/** 
 * accept a new incomming connection
 */
static void
proxy_accept(int fd, short what, void *arg)
{
        struct evproxy *proxy = arg;
        struct sockaddr_storage ss;
        socklen_t addrlen = sizeof(ss);
        int nfd;

	logx(LOG_DEBUG, "%s: do accept\n", __func__);

        if ((nfd = accept(fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
                logx(LOG_ERR, "%s: bad accept\n", __func__);
                return;
        }

        if (fcntl(nfd, F_SETFL, O_NONBLOCK) == -1) {
                logx(LOG_WARNING, "fcntl(O_NONBLOCK): %m\n");
        }

        evproxy_get_request(proxy, nfd, (struct sockaddr *)&ss, addrlen);
}

/**
 * create a new INET socket in an optional netns
 */
static int inet_socket(const char *netns)
{
	if (netns != NULL) {
		int serrno;
		int nsfd, fd;

		if ((nsfd = get_nsfd(netns)) < 0) {
			logx(LOG_ERR, "netns: %m\n");
			return -1;
		}

		fd = socketat(nsfd, AF_INET, SOCK_STREAM, 0);

		serrno = errno;
		close(nsfd);
		errno = serrno;

		return fd;
	} else
		return socket(AF_INET, SOCK_STREAM, 0);
}

/**
 * create a new socket with default settings
 */
static int get_socket(const char *netns)
{
        struct linger linger;
        int fd, on = 1;
        int serrno;

        if ((fd = inet_socket(netns)) < 0)
                return -1;

        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
                logx(LOG_ERR, "fcntl(O_NONBLOCK): %m\n");
                goto out;
        }

        if (fcntl(fd, F_SETFD, 1) == -1) {
                logx(LOG_WARNING, "fcntl(F_SETFD): %m\n");
                goto out;
	}

        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on));
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on));
        linger.l_onoff = 0;
        linger.l_linger = 5;
        setsockopt(fd, SOL_SOCKET, SO_LINGER, (void *)&linger, sizeof(linger));

        setsockopt(fd, SOL_IP, IP_TRANSPARENT, (void *)&on, sizeof(on));

	return fd;

 out:
        serrno = errno;
        close(fd);
        errno = serrno;
        return (-1);
}

/**
 * bind a listen socket
 */
static int
bind_socket(struct evproxy *proxy, struct sockaddr_in *sin)
{
        struct event *ev = &proxy->bind_ev;
        int fd, r;
        int serrno;

        /* Create listen socket */
        fd = get_socket(proxy->netns);
        if (fd == -1) {
                logx(LOG_ERR, "socket: %m\n");
                return (-1);
        }

	r = bind(fd, (struct sockaddr *)sin, sizeof(struct sockaddr_in));
        if (r == -1 && errno != EINPROGRESS)
		goto out;
	
        if (listen(fd, 10) == -1) {
                logx(LOG_ERR, "%s: listen: %m\n", __func__);
		goto out;
        }

        /* Schedule the socket for accepting */
        event_set(ev, fd, EV_READ | EV_PERSIST, proxy_accept, proxy);
        event_add(ev, NULL);

        logx(LOG_NOTICE, "Bound to port %d - Awaiting connections ...\n", ntohs(sin->sin_port));
	
        return (0);

 out:
        serrno = errno;
        close(fd);
        errno = serrno;
        return (-1);
}

static void init_sitelists(void)
{
	FILE *fin;

	fin = fopen("/tmp/etc/proxy.conf", "r");
	if (!fin)
		return;

	read_config(fin);
	fclose(fin);
}

static void init_insertions(void)
{
	char *p;
	int i;

	if (!(p = getenv("CONTENT_PATH")))
		p = ".";
	memset(insertions, 0, sizeof(insertions));
	for (i = 0; i < 16; i++) {
		char fname[PATH_MAX];

		snprintf(fname, sizeof(fname), "%s/sep_%d.html", p, i);
		insertions[i].content = readfile(fname, &insertions[i].len);
	}
}

static void free_insertions(void)
{
	int i;

	for (i = 0; i < 16; i++)
		talloc_free(insertions[i].content);
	memset(insertions, 0, sizeof(insertions));
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
	printf("TPLINO proxy gateway, Version: .....\n\n"
	       "Usage: proxy [OPTION...]\n\n"
	       "Options:\n\n"
	       "  -h                        this help\n"
	       "  -l, --log=IP              write log to syslog at this IP\n"
	       "  -x                        debug logging\n"
	       "  -p, --port=PORT           bind proxy to port (default 3128)\n"
	       "  -i, --bind=IP             bind proxy to IP\n"
	       "                            forwarded to this netblock\n"
	       "  -n, --netns=<NETNS>       open the proxy socket in a netns\n"
	       "  -a, --accesslog=<FILE|STDERR|SYSLOG>\n"
	       "                            write access log to this file, stderr or syslog\n"
	       "  -s, --buffer=SIZE         buffer size for requests (default 8k)\n\n");

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
	const char *netns = NULL;
	struct sockaddr_in bind;

	struct evproxy *proxy;

	int c;

	/* unlimited size for cores */
	setrlimit(RLIMIT_CORE, &rlim);

        bind.sin_family = AF_INET;
	bind.sin_port = htons(3128);
	bind.sin_addr.s_addr = htonl(INADDR_ANY);

	logx_level = LOG_INFO;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"log",       1, 0, 'l'},
			{"port",      1, 0, 'p'},
			{"bind",      1, 0, 'i'},
			{"accesslog", 1, 0, 'a'},
			{"netns",     1, 0, 'n'},
			{"buffer",    1, 0, 's'},
			{"resolve",   1, 0, 'r'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "a:b:f:hi:l:n:p:r:s:u:x",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			if (strcasecmp("stderr", optarg) == 0)
				access_log_dest = 2;
			else if (strcasecmp("syslog", optarg) == 0) {
				access_log_dest = 3;
				openlog(basename(argv[0]), 0, LOG_LOCAL7);
			} else if (strcasecmp("logx", optarg) == 0)
				access_log_dest = 4;
			else {
				access_log_dest = 1;
				access_log_file = strdup(optarg);
			}
			break;

		case 'h':
			usage();
			break;

		case 'i':
			if (inet_aton(optarg, &bind.sin_addr) == 0) {
				fprintf(stderr, "Invalid IP address: '%s'\n", optarg);
				exit(EXIT_FAILURE);
			}
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

		case 'p':
			bind.sin_port = htons(strtol(optarg, NULL, 0));
			if (errno != 0) {
				fprintf(stderr, "Invalid numeric argument: '%s'\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'r':
			resolv_file = strdup(optarg);
			break;

		case 'n':
			netns = strdup(optarg);
			break;

		case 's': {
			int i;

			i = strtol(optarg, NULL, 0);
			if (errno != 0) {
				fprintf(stderr, "Invalid numeric argument: '%s'\n", optarg);
				exit(EXIT_FAILURE);
			}
			if (i > proxy_buffer_size)
				proxy_buffer_size = i;
			break;

		case 'x':
			logx_level = LOG_DEBUG;
			break;
		}
		default:
			printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	logx_open(basename(argv[0]), 0, LOG_DAEMON);

	proxy = talloc(NULL, struct evproxy);
	if (!proxy)
		return 0;
	proxy->netns = netns;

        ev_base = event_init();
        if (!ev_base)
		return 1;

        signal_set(&signal_usr1, SIGUSR1, sig_usr1, &signal_usr1);
        signal_add(&signal_usr1, NULL);
        signal_set(&signal_usr2, SIGUSR2, sig_usr2, &signal_usr2);
        signal_add(&signal_usr2, NULL);
        signal_set(&signal_pipe, SIGPIPE, sig_pipe, &signal_pipe);
        signal_add(&signal_pipe, NULL);

	init_insertions();
	init_sitelists();
	
	client_init();

/*
	evdns_init();
	evdns_resolv_conf_parse(DNS_OPTIONS_ALL, resolv_file);
*/

	init_netns();
	init_comm(ev_base);

	if (bind_socket(proxy, &bind) < 0)
		return EXIT_FAILURE;

	logx(LOG_NOTICE, "startup %s %s (pid %d)\n", _ident, _build, getpid());

        event_base_loop(ev_base, 0);

        return 0;
}
