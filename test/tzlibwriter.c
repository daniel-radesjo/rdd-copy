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



#include "rdd.h"
#include "zlibwriter.c"
#include "tcpwriter.c"

#include "testhelper.h"

static int 
test_open_zlib_writer_writer_null()
{
	RDD_WRITER *parent;
	CHECK_INT(RDD_OK, rdd_open_file_writer(&parent, "testoutput"));
	CHECK_NOT_NULL_GOTO(parent);

	CHECK_INT_GOTO(RDD_BADARG, rdd_open_zlib_writer(0, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_writer_close(parent));
	CHECK_INT(0, remove("testoutput"));
	return 1;
error:
	rdd_writer_close(parent);
	remove("testoutput");
	return 0;
}


static int 
test_open_zlib_writer_parent_null()
{
	RDD_WRITER *w;
	CHECK_INT(RDD_BADARG, rdd_open_zlib_writer(&w, 0));
	return 1;
}


// TODO: tests with actual zlib writer

static int 
test_compare_address_fd_stacked_address_null()
{
	RDD_WRITER *parent;
	RDD_WRITER *w = 0;
	int result;
	CHECK_INT(RDD_OK, rdd_open_file_writer(&parent, "testoutput"));
	CHECK_NOT_NULL_GOTO(parent);

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&w, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_compare_address(w, 0, &result));
	CHECK_INT_GOTO(1, result);	

	CHECK_INT_GOTO(RDD_OK, rdd_writer_close(w));
	CHECK_INT(0, remove("testoutput"));
	return 1;
error:
	if (w == 0) {
		rdd_writer_close(parent);
	} else {
		rdd_writer_close(w);
	}
	remove("testoutput");
	return 0;
}


static int test_compare_address_fd_stacked_result_null()
{
	RDD_WRITER *parent;
	RDD_WRITER *writer = 0;
	struct addrinfo address;	// contents are irrelevant for this test

	CHECK_INT(RDD_OK, rdd_open_file_writer(&parent, "testoutput"));
	CHECK_NOT_NULL_GOTO(parent);

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_BADARG, rdd_compare_address(writer, &address, 0));	

	CHECK_INT_GOTO(RDD_OK, rdd_writer_close(writer));
	CHECK_INT(0, remove("testoutput"));
	return 1;
error:
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		rdd_writer_close(writer);
	}
	remove("testoutput");
	return 0;
}

static int test_compare_address_fd_stacked_address_not_null()
{
	RDD_WRITER *parent;
	RDD_WRITER *writer = 0;
	int result;
	struct addrinfo address;	// contents are irrelevant for this test

	CHECK_INT(RDD_OK, rdd_open_file_writer(&parent, "testoutput"));
	CHECK_NOT_NULL_GOTO(parent);

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_compare_address(writer, &address, &result));	
	CHECK_INT_GOTO(0, result);

	CHECK_INT_GOTO(RDD_OK, rdd_writer_close(writer));
	CHECK_INT(0, remove("testoutput"));
	return 1;
error:
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		rdd_writer_close(writer);
	}
	remove("testoutput");
	return 0;
}

static int 
test_compare_address_tcp_stacked_address_null()
{
	RDD_WRITER *parent;
	int result;

	// We're not using open_tcp_writer so we don't have to connect, which would require a server.
	CHECK_INT(RDD_OK, create_tcp_writer(&parent));
	CHECK_NOT_NULL_GOTO(parent);
	RDD_WRITER *writer = 0;

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_compare_address(writer, 0, &result));
	CHECK_INT_GOTO(1, result);	

	CHECK_INT(RDD_OK, zlib_cleanup(writer)); // Don't do a full close since we don't have a connected tcp writer.

	return 1;
error:
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		zlib_cleanup(writer);
	}

	return 0;
}

static int test_compare_address_tcp_stacked_result_null()
{
	RDD_WRITER *parent;
	struct addrinfo *address = 0;

	// We're not using open_tcp_writer so we don't have to connect, which would require a server.
	CHECK_INT(RDD_OK, create_tcp_writer(&parent));
	CHECK_NOT_NULL_GOTO(parent);
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address));

	RDD_WRITER *writer = 0;

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_BADARG, rdd_compare_address(writer, address, 0));	

	CHECK_INT(RDD_OK, zlib_cleanup(writer)); // Don't do a full close since we don't have a connected tcp writer.
	freeaddrinfo(address);

	return 1;
error:
	if (address != 0) {
		freeaddrinfo(address);
	}
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		zlib_cleanup(writer);
	}

	return 0;
}

static int test_compare_address_tcp_stacked_address_not_null()
{
	RDD_WRITER *parent;
	struct addrinfo *address = 0;
	int result;

	// We're not using open_tcp_writer so we don't have to connect, which would require a server.
	CHECK_INT(RDD_OK, create_tcp_writer(&parent));
	CHECK_NOT_NULL_GOTO(parent);
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address));

	RDD_WRITER *writer = 0;

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_compare_address(writer, address, &result));	
	CHECK_INT_GOTO(0, result);

	CHECK_INT(RDD_OK, zlib_cleanup(writer)); // Don't do a full close since we don't have a connected tcp writer.
	freeaddrinfo(address);

	return 1;
error:
	if (address != 0) {
		freeaddrinfo(address);
	}
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		zlib_cleanup(writer);
	}

	return 0;
}

static int test_compare_address_tcp_stacked_address_self()
{
	RDD_WRITER *parent;
	struct addrinfo *address = 0;
	int result;

	// We're not using open_tcp_writer so we don't have to connect, which would require a server.
	CHECK_INT(RDD_OK, create_tcp_writer(&parent));
	CHECK_NOT_NULL_GOTO(parent);
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(parent, address));

	RDD_WRITER *writer = 0;

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_compare_address(writer, address, &result));	
	CHECK_INT_GOTO(1, result);

	CHECK_INT(RDD_OK, zlib_cleanup(writer)); // Don't do a full close since we don't have a connected tcp writer.

	return 1;
error:
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		zlib_cleanup(writer);
	}

	return 0;
}

static int test_compare_address_tcp_stacked_address_equal()
{
	RDD_WRITER *parent;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;
	int result;

	// We're not using open_tcp_writer so we don't have to connect, which would require a server.
	CHECK_INT(RDD_OK, create_tcp_writer(&parent));
	CHECK_NOT_NULL_GOTO(parent);
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(parent, address1));


	RDD_WRITER *writer = 0;

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_compare_address(writer, address2, &result));	
	CHECK_INT_GOTO(1, result);

	CHECK_INT(RDD_OK, zlib_cleanup(writer)); // Don't do a full close since we don't have a connected tcp writer.

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		zlib_cleanup(writer);
	}

	return 0;
}

static int test_compare_address_tcp_stacked_address_same_host_different_description()
{
	RDD_WRITER *parent;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;
	int result;

	// We're not using open_tcp_writer so we don't have to connect, which would require a server.
	CHECK_INT(RDD_OK, create_tcp_writer(&parent));
	CHECK_NOT_NULL_GOTO(parent);
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("127.0.0.1", 1234, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(parent, address1));


	RDD_WRITER *writer = 0;

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_compare_address(writer, address2, &result));	
	CHECK_INT_GOTO(1, result);

	CHECK_INT(RDD_OK, zlib_cleanup(writer)); // Don't do a full close since we don't have a connected tcp writer.

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		zlib_cleanup(writer);
	}

	return 0;
}

static int test_compare_address_tcp_stacked_address_different_host()
{
	RDD_WRITER *parent;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;
	int result;

	// We're not using open_tcp_writer so we don't have to connect, which would require a server.
	CHECK_INT(RDD_OK, create_tcp_writer(&parent));
	CHECK_NOT_NULL_GOTO(parent);
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("0.0.0.0", 1234, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(parent, address1));


	RDD_WRITER *writer = 0;

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_compare_address(writer, address2, &result));	
	CHECK_INT_GOTO(0, result);

	CHECK_INT(RDD_OK, zlib_cleanup(writer)); // Don't do a full close since we don't have a connected tcp writer.

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		zlib_cleanup(writer);
	}

	return 0;
}

static int test_compare_address_tcp_stacked_address_different_port()
{
	RDD_WRITER *parent;
	struct addrinfo *address1 = 0;
	struct addrinfo *address2 = 0;
	int result;

	// We're not using open_tcp_writer so we don't have to connect, which would require a server.
	CHECK_INT(RDD_OK, create_tcp_writer(&parent));
	CHECK_NOT_NULL_GOTO(parent);
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1234, &address1));
	CHECK_INT_GOTO(RDD_OK, rdd_get_address("localhost", 1233, &address2));
	CHECK_INT_GOTO(RDD_OK, set_writer_address(parent, address1));


	RDD_WRITER *writer = 0;

	CHECK_INT_GOTO(RDD_OK, rdd_open_zlib_writer(&writer, parent));
	CHECK_INT_GOTO(RDD_OK, rdd_compare_address(writer, address2, &result));	
	CHECK_INT_GOTO(0, result);

	CHECK_INT(RDD_OK, zlib_cleanup(writer)); // Don't do a full close since we don't have a connected tcp writer.

	// address1 is freed with the writer
	freeaddrinfo(address2);

	return 1;
error:
	if (address2 != 0) {
		freeaddrinfo(address2);
	}
	if (writer == 0) {
		rdd_writer_close(parent);
	} else {
		zlib_cleanup(writer);
	}

	return 0;
}

static int
call_tests(void)
{
	int result = 1;
	TEST(test_open_zlib_writer_writer_null);
	TEST(test_open_zlib_writer_parent_null);

	TEST(test_compare_address_fd_stacked_address_null);
	TEST(test_compare_address_fd_stacked_result_null);
	TEST(test_compare_address_fd_stacked_address_not_null);

	TEST(test_compare_address_tcp_stacked_address_null);
	TEST(test_compare_address_tcp_stacked_result_null);
	TEST(test_compare_address_tcp_stacked_address_not_null);
	TEST(test_compare_address_tcp_stacked_address_self);
	TEST(test_compare_address_tcp_stacked_address_equal);
	TEST(test_compare_address_tcp_stacked_address_same_host_different_description);
	TEST(test_compare_address_tcp_stacked_address_different_host);
	TEST(test_compare_address_tcp_stacked_address_different_port);

	return result;
}

TEST_MAIN;
