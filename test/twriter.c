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


/* A unit-test for writer. This file replaces the original twriter.c file, which is now called core_writer.c.
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
#include "writer.c"

#include "testhelper.h"

static int write_called;
static int close_called;
static int compare_address_called;
static unsigned char write_buf[1024];

static void reset_called_vars()
{
	write_called = 0;
	close_called = 0;
	compare_address_called = 0;
}

static int
mock_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte)
{
	write_called = 1;
	if (nbyte <= sizeof(write_buf)) {
		memcpy(write_buf, buf, nbyte);
		return RDD_OK;
	} else {
		return RDD_EWRITE;
	}
	
}

static int 
mock_close(RDD_WRITER *w)
{
	close_called = 1;
	return RDD_OK;
}

static int 
mock_close_error(RDD_WRITER *w)
{
	close_called = 1;
	return RDD_ECLOSE;
}


static int 
mock_compare_address(RDD_WRITER *w, struct addrinfo *address, int *result)
{
	compare_address_called = 1;
	*result = 1;
	return RDD_OK;
}

static int
test_new_writer_self_null()
{
	RDD_WRITE_OPS ops;
	CHECK_UINT(RDD_BADARG, rdd_new_writer(0, &ops, 0));
	return 1;
}

static int
test_new_writer_ops_null()
{
	RDD_WRITER * writer;
	CHECK_UINT(RDD_BADARG, rdd_new_writer(&writer, 0, 0));
	return 1;
}

static int
test_new_writer_statesize_0()
{
	RDD_WRITER * writer;
	RDD_WRITE_OPS ops;
	CHECK_UINT(RDD_OK, rdd_new_writer(&writer, &ops, 0));
	return 1;
}

static int
test_new_writer()
{
	RDD_WRITER * writer;
	RDD_WRITE_OPS ops;
	ops.close = mock_close;
	CHECK_UINT(RDD_OK, rdd_new_writer(&writer, &ops, 10));
	CHECK_NOT_NULL(writer);
	CHECK_UINT(RDD_OK, rdd_writer_close(writer)); // to free resources
	return 1;
}

static int
test_writer_write()
{	
	RDD_WRITER * writer;
	RDD_WRITE_OPS ops;
	ops.write = mock_write;
	ops.close = mock_close;
	close_called = 0;
	write_called = 0;
	CHECK_UINT(RDD_OK, rdd_new_writer(&writer, &ops, 10));
	CHECK_NOT_NULL(writer);

	unsigned char input[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
	CHECK_UINT(RDD_OK, rdd_writer_write(writer, input, sizeof(input)));
	CHECK_UINT(RDD_OK, rdd_writer_close(writer)); // to free resources

	CHECK_UINT(1, write_called);
	CHECK_UCHAR_ARRAY(input, write_buf, sizeof(input));
	CHECK_UINT(1, close_called);
	return 1;
}

static int
test_writer_write_error()
{	
	RDD_WRITER * writer;
	RDD_WRITE_OPS ops;
	ops.write = mock_write;
	ops.close = mock_close;
	close_called = 0;
	write_called = 0;
	CHECK_UINT(RDD_OK, rdd_new_writer(&writer, &ops, 10));
	CHECK_NOT_NULL(writer);

	unsigned char input[1024];
	CHECK_UINT(RDD_EWRITE, rdd_writer_write(writer, input, 1025)); // size 1025 should cause an error (see mock_write)
	CHECK_UINT(RDD_OK, rdd_writer_close(writer)); // to free resources

	CHECK_UINT(1, write_called);
	CHECK_UINT(1, close_called);
	return 1;
}

static int
test_writer_close_writer_null()
{	
	CHECK_UINT(RDD_BADARG, rdd_writer_close(0));
	return 1;
}


static int
test_writer_close_error()
{	
	RDD_WRITER * writer;
	RDD_WRITE_OPS ops;
	ops.write = mock_write;
	ops.close = mock_close_error;
	close_called = 0;
	write_called = 0;
	CHECK_UINT(RDD_OK, rdd_new_writer(&writer, &ops, 10));
	CHECK_NOT_NULL(writer);

	CHECK_UINT(RDD_ECLOSE, rdd_writer_close(writer));

	CHECK_UINT(1, close_called);
	return 1;
}



static int
test_compare_address_writer_null()
{
	struct sockaddr_in addr;
	addr.sin_port = 1000;
	addr.sin_addr.s_addr = 104365;
	struct addrinfo info;
	info.ai_addr = (struct sockaddr *)&addr;
	int result;

	CHECK_UINT(RDD_BADARG, rdd_compare_address(0, &info, &result));

	return 1;
}

static int
test_compare_address()
{
	struct sockaddr_in addr;
	addr.sin_port = 1000;
	addr.sin_addr.s_addr = 104365;
	struct addrinfo info;
	info.ai_addr = (struct sockaddr *)&addr;

	RDD_WRITER * writer;
	RDD_WRITE_OPS ops;
	ops.close = mock_close;
	ops.compare_address = mock_compare_address;
	reset_called_vars();
	CHECK_UINT(RDD_OK, rdd_new_writer(&writer, &ops, 10));
	CHECK_NOT_NULL(writer);
	int result;
	
	CHECK_UINT(RDD_OK, rdd_compare_address(writer, &info, &result));
	CHECK_UINT(1, compare_address_called);
	CHECK_UINT(RDD_OK, rdd_writer_close(writer)); // to free resources
	return 1;
}

static int
test_compare_address_address_null()
{
	struct sockaddr_in addr;
	addr.sin_port = 1000;
	addr.sin_addr.s_addr = 104365;
	struct addrinfo * info = (struct addrinfo *)calloc(1, sizeof(struct addrinfo)); // allocate dynamically because rdd_writer_close will free the memory
	CHECK_NOT_NULL(info);
	info->ai_addr = (struct sockaddr *)&addr;


	RDD_WRITER * writer;
	RDD_WRITE_OPS ops;
	ops.close = mock_close;
	ops.compare_address = mock_compare_address;
	reset_called_vars();
	CHECK_UINT(RDD_OK, rdd_new_writer(&writer, &ops, 10));
	CHECK_NOT_NULL(writer);
	int result;
	
	CHECK_UINT(RDD_OK, rdd_compare_address(writer, 0, &result));
	CHECK_UINT(1, compare_address_called);
	CHECK_UINT(RDD_OK, rdd_writer_close(writer)); // to free resources
	return 1;
}



static int
call_tests(void)
{
	int result = 1;
	TEST(test_new_writer_self_null);
	TEST(test_new_writer_ops_null);
	TEST(test_new_writer_statesize_0);
	TEST(test_new_writer);

	TEST(test_writer_write);
	TEST(test_writer_write_error);

	TEST(test_writer_close_writer_null)
	TEST(test_writer_close_error);

	TEST(test_compare_address_writer_null);
	TEST(test_compare_address);
	TEST(test_compare_address_address_null);

	return result;
}

TEST_MAIN;
