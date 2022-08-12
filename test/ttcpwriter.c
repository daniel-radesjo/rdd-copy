/*
 * Copyright (c) 2002 - 2010, Netherlands Forensic Institute
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


/* A unit-test for the tcp writer. This file replaces the original ttcpwriter.c file, which is now called tpython_tcpwriter.c.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "rdd.h"
#include "tcpwriter.c"
#include "netio.h"
#include "msgprinter.h"


#include "testhelper.h"


static int test_open_tcp_writer_writer_null()
{
	CHECK_INT(RDD_BADARG, rdd_open_tcp_writer(0, "HOST", 1234));
	return 1;
}

static int test_open_tcp_writer_host_null()
{
	RDD_WRITER * writer;
	CHECK_INT(RDD_BADARG, rdd_open_tcp_writer(&writer, 0, 1234));
	return 1;
}

// TODO: more tests with actual tcpwriter

// TODO: more create_tcp_writer tests
// TODO: more get_address tests
static int
test_get_address_host_null()
{
	struct addrinfo *address;
	CHECK_INT(RDD_BADARG, rdd_get_address(0, 5555, &address));
	return 1;
}

static int
test_get_address_host_empty()
{
	struct addrinfo *address;
	CHECK_INT(RDD_BADARG, rdd_get_address("", 5555, &address));
	return 1;
}

static int
test_get_address_address_null()
{
	CHECK_INT(RDD_BADARG, rdd_get_address("localhost", 5555, 0));
	return 1;
}


// TODO: more set_writer_address tests
// TODO: more connect_tcp_writer tests

static int
test_compare_sockaddr_un_addr1_null()
{
	struct sockaddr_un addr;
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, "the path");
	
	CHECK_INT(0,  compare_sockaddr_un(0, &addr));

	return 1;
}

static int
test_compare_sockaddr_un_addr2_null()
{
	struct sockaddr_un addr;
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, "the path");
	
	CHECK_INT(0,  compare_sockaddr_un(&addr, 0));

	return 1;
}

static int
test_compare_sockaddr_un_both_null()
{
	CHECK_INT(1,  compare_sockaddr_un(0, 0));

	return 1;
}

static int
test_compare_sockaddr_un_self()
{
	struct sockaddr_un addr;
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, "the path");
	
	CHECK_INT(1,  compare_sockaddr_un(&addr, &addr));

	return 1;
}

static int
test_compare_sockaddr_un_equal()
{
	struct sockaddr_un addr1;
	addr1.sun_family = AF_LOCAL;
	strcpy(addr1.sun_path, "the path");
	struct sockaddr_un addr2;
	addr2.sun_family = AF_LOCAL;
	strcpy(addr2.sun_path, "the path");	

	CHECK_INT(1,  compare_sockaddr_un(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_un_different_family()
{
	struct sockaddr_un addr1;
	addr1.sun_family = AF_LOCAL;
	strcpy(addr1.sun_path, "the path");
	struct sockaddr_un addr2;
	addr2.sun_family = AF_INET; // a bit of a strange family for sockaddr_un; just for testing purposes
	strcpy(addr2.sun_path, "the path");	

	CHECK_INT(0,  compare_sockaddr_un(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_un_different_path()
{
	struct sockaddr_un addr1;
	addr1.sun_family = AF_LOCAL;
	strcpy(addr1.sun_path, "the path");
	struct sockaddr_un addr2;
	addr2.sun_family = AF_LOCAL;
	strcpy(addr2.sun_path, "the pat");	

	CHECK_INT(0,  compare_sockaddr_un(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_in_addr1_null()
{
	struct sockaddr_in addr;
	addr.sin_port = 1000;
	addr.sin_addr.s_addr = 104365;
	
	CHECK_INT(0,  compare_sockaddr_in(0, &addr));

	return 1;
}

static int
test_compare_sockaddr_in_addr2_null()
{
	struct sockaddr_in addr;
	addr.sin_port = 1000;
	addr.sin_addr.s_addr = 104365;
	
	CHECK_INT(0,  compare_sockaddr_in(&addr, 0));

	return 1;
}

static int
test_compare_sockaddr_in_both_null()
{
	CHECK_INT(1,  compare_sockaddr_in(0, 0));

	return 1;
}

static int
test_compare_sockaddr_in_self()
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = 1000;
	addr.sin_addr.s_addr = 104365;
	
	CHECK_INT(1,  compare_sockaddr_in(&addr, &addr));

	return 1;
}

static int
test_compare_sockaddr_in_equal()
{
	struct sockaddr_in addr1;
	addr1.sin_family = AF_INET;
	addr1.sin_port = 1000;
	addr1.sin_addr.s_addr = 104365;

	struct sockaddr_in addr2;
	addr2.sin_family = AF_INET;
	addr2.sin_port = 1000;
	addr2.sin_addr.s_addr = 104365;
	CHECK_INT(1,  compare_sockaddr_in(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_in_different_family()
{
	struct sockaddr_in addr1;
	addr1.sin_family = AF_LOCAL;// a bit of a strange family for sockaddr_in; just for testing purposes
	addr1.sin_port = 1000;
	addr1.sin_addr.s_addr = 104365;

	struct sockaddr_in addr2;
	addr2.sin_family = AF_INET; 
	addr2.sin_port = 1000;
	addr2.sin_addr.s_addr = 104365;

	CHECK_INT(0,  compare_sockaddr_in(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_in_different_address()
{
	struct sockaddr_in addr1;
	addr1.sin_family = AF_INET;
	addr1.sin_port = 1000;
	addr1.sin_addr.s_addr = 104365;

	struct sockaddr_in addr2;
	addr2.sin_family = AF_INET;
	addr2.sin_port = 1000;
	addr2.sin_addr.s_addr = 104364;	

	CHECK_INT(0,  compare_sockaddr_in(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_in_different_port()
{
	struct sockaddr_in addr1;
	addr1.sin_family = AF_INET;
	addr1.sin_port = 1000;
	addr1.sin_addr.s_addr = 104365;

	struct sockaddr_in addr2;
	addr2.sin_family = AF_INET;
	addr2.sin_port = 1001;
	addr2.sin_addr.s_addr = 104365;	

	CHECK_INT(0,  compare_sockaddr_in(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_in6_addr1_null()
{
	struct sockaddr_in6 addr;
	addr.sin6_family = AF_INET6;
	int i;
	for (i=0; i<16; i++) {
		addr.sin6_addr.s6_addr[i] = i;
	}
	addr.sin6_port = 1000;
	
	CHECK_INT(0,  compare_sockaddr_in6(0, &addr));

	return 1;
}

static int
test_compare_sockaddr_in6_addr2_null()
{
	struct sockaddr_in6 addr;
	addr.sin6_family = AF_INET6;
	int i;
	for (i=0; i<16; i++) {
		addr.sin6_addr.s6_addr[i] = i;
	}
	addr.sin6_port = 1000;
	
	CHECK_INT(0,  compare_sockaddr_in6(&addr, 0));

	return 1;
}

static int
test_compare_sockaddr_in6_both_null()
{
	CHECK_INT(1,  compare_sockaddr_in6(0, 0));

	return 1;
}

static int
test_compare_sockaddr_in6_self()
{
	struct sockaddr_in6 addr;
	addr.sin6_family = AF_INET6;
	addr.sin6_port = 1000;
	int i;
	for (i=0; i<16; i++) {
		addr.sin6_addr.s6_addr[i] = i;
	}
	CHECK_INT(1,  compare_sockaddr_in6(&addr, &addr));

	return 1;
}

static int
test_compare_sockaddr_in6_equal()
{
	struct sockaddr_in6 addr1;
	addr1.sin6_family = AF_INET6;
	addr1.sin6_port = 1000;
	int i;
	for (i=0; i<16; i++) {
		addr1.sin6_addr.s6_addr[i] = i;
	}

	struct sockaddr_in6 addr2;
	addr2.sin6_family = AF_INET6;
	addr2.sin6_port = 1000;
	for (i=0; i<16; i++) {
		addr2.sin6_addr.s6_addr[i] = i;
	}
	CHECK_INT(1,  compare_sockaddr_in6(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_in6_different_family()
{
	struct sockaddr_in6 addr1;
	addr1.sin6_family = AF_INET;// a bit of a strange family for sockaddr_in6; just for testing purposes
	addr1.sin6_port = 1000;
	int i;
	for (i=0; i<16; i++) {
		addr1.sin6_addr.s6_addr[i] = i;
	}

	struct sockaddr_in6 addr2;
	addr2.sin6_family = AF_INET6; 
	addr2.sin6_port = 1000;
	for (i=0; i<16; i++) {
		addr2.sin6_addr.s6_addr[i] = i;
	}
	CHECK_INT(0,  compare_sockaddr_in6(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_in6_different_address()
{
	struct sockaddr_in6 addr1;
	addr1.sin6_family = AF_INET6;
	addr1.sin6_port = 1000;
	int i;
	for (i=0; i<16; i++) {
		addr1.sin6_addr.s6_addr[i] = i;
	}

	struct sockaddr_in6 addr2;
	addr2.sin6_family = AF_INET6; 
	addr2.sin6_port = 1000;
	for (i=0; i<16; i++) {
		addr2.sin6_addr.s6_addr[i] = i;
	}
	addr2.sin6_addr.s6_addr[6] = 0; // to create a difference

	CHECK_INT(0,  compare_sockaddr_in6(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_in6_different_port()
{
	struct sockaddr_in6 addr1;
	addr1.sin6_family = AF_INET6;
	addr1.sin6_port = 1000;
	int i;
	for (i=0; i<16; i++) {
		addr1.sin6_addr.s6_addr[i] = i;
	}

	struct sockaddr_in6 addr2;
	addr2.sin6_family = AF_INET6;
	addr2.sin6_port = 988;
	for (i=0; i<16; i++) {
		addr2.sin6_addr.s6_addr[i] = i;
	}
	CHECK_INT(0,  compare_sockaddr_in6(&addr1, &addr2));

	return 1;
}

static int
test_compare_sockaddr_addr1_null()
{
	struct sockaddr_in addr;
	addr.sin_port = 1000;
	addr.sin_addr.s_addr = 104365;
	
	CHECK_INT(0,  compare_sockaddr(0, (struct sockaddr *)&addr));

	return 1;
}

static int
test_compare_sockaddr_addr2_null()
{
	struct sockaddr_in addr;
	addr.sin_port = 1000;
	addr.sin_addr.s_addr = 104365;
	
	CHECK_INT(0,  compare_sockaddr((struct sockaddr *)&addr, 0));

	return 1;
}

static int
test_compare_sockaddr_both_null()
{
	CHECK_INT(1,  compare_sockaddr(0, 0));

	return 1;
}


static int
test_compare_sockaddr_self()
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = 1000;
	addr.sin_addr.s_addr = 104365;

	CHECK_INT(1,  compare_sockaddr((struct sockaddr *)&addr, (struct sockaddr *)&addr));

	return 1;
}

static int
test_compare_sockaddr_equal()
{
	struct sockaddr_in addr1;
	addr1.sin_family = AF_INET;
	addr1.sin_port = 1000;
	addr1.sin_addr.s_addr = 104365;

	struct sockaddr_in addr2;
	addr2.sin_family = AF_INET;
	addr2.sin_port = 1000;
	addr2.sin_addr.s_addr = 104365;
	CHECK_INT(1,  compare_sockaddr((struct sockaddr *)&addr1, (struct sockaddr *)&addr2));

	return 1;
}

static int
test_compare_sockaddr_different_family()
{
	struct sockaddr_un addr1;
	addr1.sun_family = AF_LOCAL;
	strcpy(addr1.sun_path, "the path");

	struct sockaddr_in addr2;
	addr2.sin_family = AF_INET; 
	addr2.sin_port = 1000;
	addr2.sin_addr.s_addr = 104365;

	CHECK_INT(0,  compare_sockaddr((struct sockaddr *)&addr1, (struct sockaddr *)&addr2));

	return 1;
}

static int
test_compare_sockaddr_different_address()
{
	struct sockaddr_in addr1;
	addr1.sin_family = AF_INET;
	addr1.sin_port = 1000;
	addr1.sin_addr.s_addr = 104365;

	struct sockaddr_in addr2;
	addr2.sin_family = AF_INET;
	addr2.sin_port = 1000;
	addr2.sin_addr.s_addr = 10436;

	CHECK_INT(0,  compare_sockaddr((struct sockaddr *)&addr1, (struct sockaddr *)&addr2));

	return 1;
}

static int
test_compare_sockaddr_different_port()
{
	struct sockaddr_in addr1;
	addr1.sin_family = AF_INET;
	addr1.sin_port = 1000;
	addr1.sin_addr.s_addr = 104365;

	struct sockaddr_in addr2;
	addr2.sin_family = AF_INET;
	addr2.sin_port = 1002;
	addr2.sin_addr.s_addr = 104365;

	CHECK_INT(0, compare_sockaddr((struct sockaddr *)&addr1, (struct sockaddr *)&addr2));

	return 1;
}

static int
test_compare_writer_address_writer_null()
{
	struct addrinfo *address = 0;
	CHECK_INT(RDD_OK, rdd_get_address("localhost", 1234, &address));

	CHECK_INT(0,  compare_writer_address(0, address));

	freeaddrinfo(address);

	return 1;
}

static int
test_compare_writer_address_writer_address_null()
{
	RDD_WRITER *w;
	struct addrinfo *address = 0;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address));
	
	CHECK_INT_GOTO(0,  compare_writer_address(w, address));
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	freeaddrinfo(address);

	return 1;
error:
	if (address != 0) {
		freeaddrinfo(address);
	}
	rdd_writer_close(w);
	return 0;
}

static int
test_compare_writer_address_comparison_address_null()
{
	RDD_WRITER *w;
	struct addrinfo *address = 0;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address));
	
	CHECK_INT_GOTO(0,  compare_writer_address(w, 0));
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	return 1;
error:
	rdd_writer_close(w);
	return 0;
}


static int
test_compare_writer_address_self()
{
	RDD_WRITER *w;
	struct addrinfo *address = 0;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address));

	CHECK_INT_GOTO(1,  compare_writer_address(w, address));
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	return 1;
error:
	rdd_writer_close(w);
	return 0;
}

static int
test_compare_writer_address_equal()
{
	RDD_WRITER *w;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address1));

	CHECK_INT_GOTO(1,  compare_writer_address(w, address2));
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	rdd_writer_close(w);
	return 0;
}

static int
test_compare_writer_address_same_host_different_description()
{
	RDD_WRITER *w;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("127.0.0.1", 1234, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address1));

	CHECK_INT_GOTO(1,  compare_writer_address(w, address2));
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	rdd_writer_close(w);
	return 0;
}

static int
test_compare_writer_address_different_host()
{
	RDD_WRITER *w;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("0.0.0.0", 1234, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address1));

	CHECK_INT_GOTO(0,  compare_writer_address(w, address2));
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	rdd_writer_close(w);
	return 0;
}

static int
test_compare_writer_address_different_port()
{
	RDD_WRITER *w;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1233, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address1));

	CHECK_INT_GOTO(0,  compare_writer_address(w, address2));
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	rdd_writer_close(w);
	freeaddrinfo(address2);
	return 0;
}

static int
test_tcp_compare_address_writer_null()
{
	struct addrinfo *address = 0;
	int result;

	CHECK_INT(RDD_OK, rdd_get_address("localhost", 1234, &address));

	CHECK_INT(RDD_BADARG,  tcp_compare_address(0, address, &result));

	freeaddrinfo(address);

	return 1;
}

static int
test_tcp_compare_address_writer_address_null()
{
	RDD_WRITER *w;
	struct addrinfo *address = 0;
	int result;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address));

	CHECK_INT_GOTO(RDD_OK,  tcp_compare_address(w, address, &result));
	CHECK_INT_GOTO(0, result);
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	freeaddrinfo(address);

	return 1;
error:
	if (address != 0) {
		freeaddrinfo(address);		
	}
	rdd_writer_close(w);
	return 0;
}

static int
test_tcp_compare_address_comparison_address_null()
{
	RDD_WRITER *w;
	struct addrinfo *address = 0;
	int result;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address));

	CHECK_INT_GOTO(RDD_OK,  tcp_compare_address(w, 0, &result));
	CHECK_INT_GOTO(0, result);
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	return 1;
error:
	rdd_writer_close(w);
	return 0;
}


static int
test_tcp_compare_address_self()
{
	RDD_WRITER *w;
	struct addrinfo *address = 0;
	int result;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address));

	CHECK_INT_GOTO(RDD_OK,  tcp_compare_address(w, address, &result));
	CHECK_INT_GOTO(1, result);
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	return 1;
error:
	rdd_writer_close(w);
	return 0;
}

static int
test_tcp_compare_address_equal()
{
	RDD_WRITER *w;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;
	int result;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address1));

	CHECK_INT_GOTO(RDD_OK,  tcp_compare_address(w, address2, &result));
	CHECK_INT_GOTO(1, result);
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources
	// address1 is freed with the writer
	freeaddrinfo(address2);
	return 1;
error:
	rdd_writer_close(w);
	freeaddrinfo(address2);
	return 0;
}

static int
test_tcp_compare_address_same_host_different_description()
{
	RDD_WRITER *writer;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;
	int result;

	CHECK_INT(RDD_OK, create_tcp_writer(&writer));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("127.0.0.1", 1234, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(writer, address1));

	CHECK_INT_GOTO(RDD_OK,  tcp_compare_address(writer, address2, &result));
	CHECK_INT_GOTO(1, result);
	CHECK_INT(RDD_OK, rdd_writer_close(writer)); // to free resources

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	rdd_writer_close(writer);
	return 0;
}

static int
test_tcp_compare_address_different_host()
{
	RDD_WRITER *w;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;
	int result;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("0.0.0.0", 1234, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address1));

	CHECK_INT_GOTO(RDD_OK,  tcp_compare_address(w, address2, &result));
	CHECK_INT_GOTO(0, result);
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	rdd_writer_close(w);
	return 0;
}

static int
test_tcp_compare_address_different_port()
{
	RDD_WRITER *w;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;
	int result;

	CHECK_INT(RDD_OK, create_tcp_writer(&w));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1233, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(w, address1));

	CHECK_INT_GOTO(RDD_OK,  tcp_compare_address(w, address2, &result));
	CHECK_INT_GOTO(0, result);
	CHECK_INT(RDD_OK, rdd_writer_close(w)); // to free resources

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	rdd_writer_close(w);
	return 0;

}

static int
call_tests(void)
{
	int result = 1;
	TEST(test_open_tcp_writer_writer_null);
	TEST(test_open_tcp_writer_host_null);

	TEST(test_get_address_host_null);
	TEST(test_get_address_host_empty);
	TEST(test_get_address_address_null);

	TEST(test_compare_sockaddr_un_addr1_null);
	TEST(test_compare_sockaddr_un_addr2_null);
	TEST(test_compare_sockaddr_un_both_null);
	TEST(test_compare_sockaddr_un_self);
	TEST(test_compare_sockaddr_un_equal);
	TEST(test_compare_sockaddr_un_different_family);
	TEST(test_compare_sockaddr_un_different_path);

	TEST(test_compare_sockaddr_in_addr1_null);
	TEST(test_compare_sockaddr_in_addr2_null);
	TEST(test_compare_sockaddr_in_both_null);
	TEST(test_compare_sockaddr_in_self);
	TEST(test_compare_sockaddr_in_equal);
	TEST(test_compare_sockaddr_in_different_family);
	TEST(test_compare_sockaddr_in_different_address);
	TEST(test_compare_sockaddr_in_different_port);

	TEST(test_compare_sockaddr_in6_addr1_null);
	TEST(test_compare_sockaddr_in6_addr2_null);
	TEST(test_compare_sockaddr_in6_both_null);
	TEST(test_compare_sockaddr_in6_self);
	TEST(test_compare_sockaddr_in6_equal);
	TEST(test_compare_sockaddr_in6_different_family);
	TEST(test_compare_sockaddr_in6_different_address);
	TEST(test_compare_sockaddr_in6_different_port);

	TEST(test_compare_sockaddr_addr1_null);
	TEST(test_compare_sockaddr_addr2_null);
	TEST(test_compare_sockaddr_both_null);
	TEST(test_compare_sockaddr_self);
	TEST(test_compare_sockaddr_equal);
	TEST(test_compare_sockaddr_different_family);
	TEST(test_compare_sockaddr_different_address);
	TEST(test_compare_sockaddr_different_port);

	TEST(test_compare_writer_address_writer_null);
	TEST(test_compare_writer_address_writer_address_null);
	TEST(test_compare_writer_address_comparison_address_null);
	TEST(test_compare_writer_address_self);
	TEST(test_compare_writer_address_equal);
	TEST(test_compare_writer_address_same_host_different_description);
	TEST(test_compare_writer_address_different_host);
	TEST(test_compare_writer_address_different_port);
	
	TEST(test_tcp_compare_address_writer_null);
	TEST(test_tcp_compare_address_writer_address_null);
	TEST(test_tcp_compare_address_comparison_address_null);
	TEST(test_tcp_compare_address_self);
	TEST(test_tcp_compare_address_equal);
	TEST(test_tcp_compare_address_same_host_different_description);
	TEST(test_tcp_compare_address_different_host);
	TEST(test_tcp_compare_address_different_port);

	return result;

}

TEST_MAIN;
