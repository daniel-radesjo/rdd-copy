/*
 * Copyright (c) 2002 - 2006, Netherlands Forensic Institute
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.

 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#if 0
// gives a conflict with zlibwriter.c in tzlibwriter test
#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 2002-2004\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/un.h>

#include "rdd.h"
#include "writer.h"

/* Forward declarations
 */
static int tcp_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte);
static int tcp_close(RDD_WRITER *w);
static int tcp_compare_address(RDD_WRITER *w, struct addrinfo *address, int *result);

static RDD_WRITE_OPS tcp_write_ops = {
	tcp_write,
	tcp_close,
	tcp_compare_address
};

typedef struct _RDD_TCP_WRITER {
	struct addrinfo *address;
	RDD_WRITER *parent;
} RDD_TCP_WRITER;

static int
create_tcp_writer(RDD_WRITER **self)
{
	RDD_WRITER *w = 0;
	int rc;

	if (self == 0) {
		return RDD_BADARG;
	}

	rc = rdd_new_writer(&w, &tcp_write_ops, sizeof(RDD_TCP_WRITER));
	if (rc != RDD_OK) {
		return rc;
	}
	RDD_TCP_WRITER *state = w->state;
	state->parent = 0;
	state->address = 0;

	*self = w;
	return RDD_OK;
}

/* public function (see writer.h) */
int
rdd_get_address(const char *host, unsigned int port, struct addrinfo ** addr)
{
	struct addrinfo info;
	char service_name[16];

	if (host == 0 || strlen(host) == 0) {
		return RDD_BADARG;
	}
	if (addr == 0) {
		return RDD_BADARG;
	}

	memset((char *)&info, '\000', sizeof(struct addrinfo));
	info.ai_socktype = SOCK_STREAM;

	if (snprintf(service_name, sizeof(service_name), "%u", port) >= sizeof(service_name)) {
		return RDD_BADARG;
	}

	if (getaddrinfo(host, service_name, &info, addr) != 0) {
		return RDD_ECONNECT;
	}

	return RDD_OK;


}

static int
set_writer_address(RDD_WRITER *w, struct addrinfo * addr)
{
	if (w == 0) {
		return RDD_BADARG;
	}
	RDD_TCP_WRITER *state = w->state;
		
	state->address = addr;

	return RDD_OK;
}

static int
connect_tcp_writer(RDD_WRITER *w)
{
	int sock = -1;
	int rc;

	RDD_TCP_WRITER *state = w->state;
		
	struct addrinfo * addr = state->address;

	if ((sock = socket(addr->ai_family, SOCK_STREAM, 0)) < 0) {
		return RDD_ECONNECT;
	}

	if (connect(sock, addr->ai_addr, addr->ai_addrlen) < 0) {
		return RDD_ECONNECT;
	}

	rc = rdd_open_fd_writer(&state->parent, sock);
	if (rc != RDD_OK) {
		return rc;
	}
	return RDD_OK;
}

int
rdd_open_tcp_writer(RDD_WRITER **self, const char *host, unsigned int port)
{
	int rc;
	rc = create_tcp_writer(self);
	if (rc != RDD_OK) {
		return rc;
	}
	struct addrinfo *address;

	rc = rdd_get_address(host, port, &address);
	if (rc != RDD_OK) {
		goto error;
	}

	rc = set_writer_address(*self, address);
	if (rc != RDD_OK) {
		goto error;
	}

	rc = connect_tcp_writer(*self);
	if (rc != RDD_OK) {
		goto error;
	}
	return RDD_OK;

error:
	rdd_writer_close(*self);
	return rc;
}

static int
tcp_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte)
{
	if (w == 0) {
		return RDD_BADARG;
	}
	RDD_TCP_WRITER *state = w->state;

	if (state->parent == 0) {
		return RDD_EWRITE;
	}
	return rdd_writer_write(state->parent, buf, nbyte);
}

static int
tcp_close(RDD_WRITER *self)
{
	RDD_TCP_WRITER *state = self->state;
	int rc;

	if (state->parent != 0) {
		if ((rc = rdd_writer_close(state->parent)) != RDD_OK) {
			return rc;
		}
	}

	if (state->address != 0) {
		freeaddrinfo(state->address);
	}

	return RDD_OK;
}

static int
compare_sockaddr_un(struct sockaddr_un * address1, struct sockaddr_un * address2)
{
	if (address1 == 0) {
		return (address2 == 0);
	}
	if (address2 == 0) {
		return 0;
	}

	if (address1->sun_family != address2->sun_family) {
		return 0;
	}
	return !strcmp(address1->sun_path, address2->sun_path);
}

static int
compare_sockaddr_in(struct sockaddr_in * address1, struct sockaddr_in * address2)
{
	if (address1 == 0) {
		return (address2 == 0);
	}
	if (address2 == 0) {
		return 0;
	}

	if (address1->sin_family != address2->sin_family) {
		return 0;
	}

	if (address1->sin_addr.s_addr != address2->sin_addr.s_addr) {
		return 0;
	}
	return address1->sin_port == address2->sin_port;
}

static int
compare_sockaddr_in6(struct sockaddr_in6 * address1, struct sockaddr_in6 * address2)
{
	if (address1 == 0) {
		return (address2 == 0);
	}
	if (address2 == 0) {
		return 0;
	}

	if (address1->sin6_family != address2->sin6_family) {
		return 0;
	}

	if (memcmp(address1->sin6_addr.s6_addr, address2->sin6_addr.s6_addr, sizeof(address1->sin6_addr.s6_addr))) {
		return 0;
	}
	
	return address1->sin6_port == address2->sin6_port;
}


static int
compare_sockaddr(struct sockaddr * address1, struct sockaddr * address2)
{
	if (address1 == 0) {
		return (address2 == 0);
	}
	if (address2 == 0) {
		return 0;
	}
	if (address1->sa_family != address2->sa_family) {
		return 0;
	}
	switch(address1->sa_family) {
		case PF_LOCAL:
			return compare_sockaddr_un((struct sockaddr_un *)address1, (struct sockaddr_un *)address2);
			break;
		case AF_INET:
			return compare_sockaddr_in((struct sockaddr_in *)address1, (struct sockaddr_in *)address2);
		case AF_INET6:
			return compare_sockaddr_in6((struct sockaddr_in6 *)address1, (struct sockaddr_in6 *)address2);
			break;
		case AF_UNSPEC:
		default:
			return 0; // don't know how to handle this, so assume all addresses are different
			break;

	}
}

static int 
compare_writer_address(RDD_WRITER *w, struct addrinfo * address)
{
	if (w == 0) {
		return 0;
	}
	RDD_TCP_WRITER *state = w->state;

	if (state->address == 0) {
		return (address == 0);
	}

	if (address == 0) {
		return 0;
	}
	return compare_sockaddr(state->address->ai_addr, address->ai_addr);
}

static int
tcp_compare_address(RDD_WRITER *w, struct addrinfo * address, int *result)
{
	if (w == 0) {
		return RDD_BADARG;
	}
	if (result == 0) {
		return RDD_BADARG;
	}
	*result = compare_writer_address(w, address);
	return RDD_OK;
}

