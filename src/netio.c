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


/*
 * $Author: raoul $
 * $LastChangedBy: kojak $
 * $LastChangedDate: 2003-01-02 19:32:23 +0100 (Thu, 02 Jan 2003) $
 */

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 2002\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */

/*
 * TCP support
 *
 * TODO: add checksumming.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"
#include "msgprinter.h"
#include "reader.h"
#include "writer.h"
#include "netio.h"

#if !defined(HAVE_UNISTD_H) && !defined (HAVE_ARPA_INET_H) && !defined(HAVE_SYS_SOCKET_H)
typedef int socklen_t;
#endif

/* Holds a 64-bit number in network format.
 */
struct netnum {
	unsigned lo;
	unsigned hi;
};

static int net_verbose;

static int
pack_netnum(struct netnum *packed, rdd_count_t num)
{
	if (packed == 0) {
		return RDD_BADARG;
	}
	packed->hi = htonl((num >> 32) & 0xffffffff);
	packed->lo = htonl(num & 0xffffffff);
	return RDD_OK;
}

static int
unpack_netnum(struct netnum *packed, rdd_count_t *num)
{
	if (packed == 0) {
		return RDD_BADARG;
	}
	if (num == 0) {
		return RDD_BADARG;
	}
	
	rdd_count_t lo, hi;

	hi = (rdd_count_t) ntohl(packed->hi);
	lo = (rdd_count_t) ntohl(packed->lo);
	*num = (hi << 32) | lo;
	return RDD_OK;
}


/* Before any data is sent from the client to the server, the
 * client sends some metadata to the server.  The following information
 * is sent:
 * - length of output file name including terminating null byte (64 bits)
 * - file size (64 bits)
 * - block size (64 bits)
 * - output file name, including terminating null byte
 *
 * These items are transmitted by rdd_send_info and received by
 * rdd_recv_info.
 */
int
rdd_send_info(RDD_WRITER *writer, char *file_name,
		rdd_count_t file_size,
		rdd_count_t block_size,
		rdd_count_t split_size,
		int ewf,
		unsigned flags)
{
	struct netnum hdr[6];
	unsigned flen;
	int rc;
	
	if (writer == 0) {
		return RDD_BADARG;
	}
	if (file_name == 0) {
		return RDD_BADARG;
	}

	flen = strlen(file_name) + 1;
	if (flen > RDD_MAX_FILENAMESIZE) {
		return RDD_ERANGE;
	}

	rc = pack_netnum(&hdr[0], (rdd_count_t) flen);
	if (rc != RDD_OK) {
		return rc;
	}
	rc = pack_netnum(&hdr[1], file_size);
	if (rc != RDD_OK) {
		return rc;
	}
	rc = pack_netnum(&hdr[2], block_size);
	if (rc != RDD_OK) {
		return rc;
	}
	rc = pack_netnum(&hdr[3], split_size);
	if (rc != RDD_OK) {
		return rc;
	}
	rc = pack_netnum(&hdr[4], ewf);
	if (rc != RDD_OK) {
		return rc;
	}
	rc = pack_netnum(&hdr[5], (rdd_count_t) flags);
	if (rc != RDD_OK) {
		return rc;
	}

	rc = rdd_writer_write(writer,
			(const unsigned char *) hdr, sizeof hdr);
	if (rc != RDD_OK) {
		return rc;
	}

	rc = rdd_writer_write(writer, (unsigned char *) file_name, flen);
	if (rc != RDD_OK) {
		return rc;
	}

	/* TODO: add header checksum */

	return RDD_OK;
}

/* Reads exactly buflen bytes into buffer buf using reader.
 */
static int
receive(RDD_READER *reader, unsigned char *buf, unsigned buflen)
{
	unsigned nread = 0;
	int rc;

	if (reader == 0) {
		return RDD_BADARG;
	}

	if (buf == 0) {
		return RDD_BADARG;
	}

	rc = rdd_reader_read(reader, buf, buflen, &nread);
	if (rc != RDD_OK) {
		return rc;
	}
	if (nread != buflen) {
		return RDD_ESYNTAX;
	}

	return RDD_OK;
}


/* Receives a copy request header from an rdd client and extracts
 * all information from that header.
 */
int
rdd_recv_info(RDD_READER *reader, char **file_name,
		rdd_count_t *file_size,
		rdd_count_t *block_size,
		rdd_count_t *split_size,
		int * ewf,
		unsigned *flagp)
{
	struct netnum hdr[6];
	rdd_count_t flen;
	rdd_count_t flags;
	int rc;

	if (reader == 0) {
		return RDD_BADARG;
	}
	if (file_name == 0) {
		return RDD_BADARG;
	}
	if (file_size == 0) {
		return RDD_BADARG;
	}
	if (block_size == 0) {
		return RDD_BADARG;
	}
	if (split_size == 0) {
		return RDD_BADARG;
	}
	if (ewf == 0) {
		return RDD_BADARG;
	}
	if (flagp == 0) {
		return RDD_BADARG;
	}


	rc = receive(reader, (unsigned char *) &hdr, sizeof hdr);
	if (rc != RDD_OK) {
		return rc;
	}

	/* TODO: verify header checksum */

	rc = unpack_netnum(&hdr[0], &flen);
	if (rc != RDD_OK) {
		return rc;
	}
	rc = unpack_netnum(&hdr[1], file_size);
	if (rc != RDD_OK) {
		return rc;
	}
	rc = unpack_netnum(&hdr[2], block_size);
	if (rc != RDD_OK) {
		return rc;
	}
	rc = unpack_netnum(&hdr[3], split_size);
	if (rc != RDD_OK) {
		return rc;
	}
	rdd_count_t temp_ewf;
	rc = unpack_netnum(&hdr[4], &temp_ewf);
	if (rc != RDD_OK) {
		return rc;
	}
	if (temp_ewf) {
		*ewf = temp_ewf;
	} else {
		*ewf = 0;
	}
	rc = unpack_netnum(&hdr[5], &flags);
	if (rc != RDD_OK) {
		return rc;
	}

	*flagp = (unsigned) flags;

	if (flen > RDD_MAX_FILENAMESIZE) {
		return RDD_ERANGE;
	}

	if (flen == 0) { // flen = 1 can occur with end-of-output-opts marker
		return RDD_ESYNTAX;
	}

	if ((*file_name = malloc(flen)) == 0) {
		return RDD_NOMEM;
	}

	rc = receive(reader, (unsigned char *) *file_name, flen);
	if (rc != RDD_OK) {
		return rc;
	}
	if (*file_name != '\0') { // '\0' occurs here on end-of-output-opts marker
		if ((*file_name)[flen-1] != '\0') {
			return RDD_ESYNTAX;
		}
	}

	return RDD_OK;
}

int
rdd_init_server(RDD_MSGPRINTER *printer, unsigned int port, int *server_sock)
{
	struct sockaddr_in addr;
	int sock = -1;
	int on = 1;


	if (server_sock == 0) {
		return RDD_BADARG;
	}
	if (printer == 0) {
		*server_sock = -1;
		return RDD_BADARG;
	}

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot create TCP socket");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot set socket option SO_REUSEADDR");
		goto error;
	}

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot bind TCP socket to local port %u", port);
		goto error;
	}

	if (listen(sock, 5) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot listen to TCP socket");
		goto error;
	}

	*server_sock = sock;
	return RDD_OK;

error:
	if (sock != -1)  {
		(void) close(sock);
	}
	*server_sock = -1;
	return RDD_EOPEN;
}

int
rdd_await_connection(RDD_MSGPRINTER *printer, int server_sock,
	int *client_sock)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int clsock = -1;


	if (client_sock == 0) {
		return RDD_BADARG;
	}
	if (printer == 0) {
		*client_sock = -1;
		return RDD_BADARG;
	}

	if ((clsock = accept(server_sock, (struct sockaddr *)&addr, &len)) < 0) {
		rdd_mp_unixmsg(printer, RDD_MSG_ERROR, errno, 
			"cannot accept client connection");
		goto error;
	}

	if (net_verbose) {
		rdd_mp_message(printer, RDD_MSG_INFO, 
			"Accepted inbound connection from %s",
			inet_ntoa(addr.sin_addr));
	}

	*client_sock = clsock;
	return RDD_OK;

error:
	if (clsock != -1) {
		(void) close(clsock);
	}
	*client_sock = -1;
	return RDD_EOPEN;
}
