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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>

#include "rdd.h"
#include "filter.h"
#include "mockstreamfilter.h"
#include "mockblockfilter.h"
#include "testhelper.h"

#define BLOCK_SIZE 2

static RDD_FILTER *mockstreamfilter, *mockblockfilter;

static int
setup()
{
	CHECK_UINT(RDD_OK, mockstreamfilter_open(&mockstreamfilter));
	CHECK_UINT(RDD_OK, mockblockfilter_open(&mockblockfilter, BLOCK_SIZE));

	return 1;
}

static int
teardown()
{
	CHECK_UINT(RDD_OK, rdd_filter_free(mockstreamfilter));
	CHECK_UINT(RDD_OK, rdd_filter_free(mockblockfilter));
	return 1;
}

static int
test_new_filter_self_null()
{
	CHECK_UINT(RDD_BADARG, rdd_new_filter(0, mockstreamfilter->ops, sizeof(mockstreamfilter->state),0 ));

	return 1;
}

static int
test_new_filter_ops_null()
{
	RDD_FILTER *self;

	CHECK_UINT(RDD_BADARG, rdd_new_filter(&self, 0, sizeof(mockstreamfilter->state),0));

	return 1;
}

static int
test_new_filter_blockfilter_blocksize_0()
{
	RDD_FILTER *self;

	CHECK_UINT(RDD_BADARG, rdd_new_filter(&self, mockblockfilter->ops, sizeof(mockblockfilter->state),0));

	return 1;
}

static int
test_new_filter_streamfilter_with_blocksize()
{
	RDD_FILTER *self;
	CHECK_UINT(RDD_BADARG, rdd_new_filter(&self, mockstreamfilter->ops, sizeof(mockstreamfilter->state),512));

	return 1;
}

static int
test_streamfilter_push_succes()
{
	unsigned char test_buf[5] = { 0, 1, 2, 3, 4 };
	unsigned nbyte = 5;

	mockstreamfilter_stub_input(mockstreamfilter, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_filter_push(mockstreamfilter, test_buf,nbyte));

	CHECK_TRUE(mockstreamfilter_verify_input(mockstreamfilter,1, test_buf, nbyte));

	return 1;
}

static int
test_blockfilter_push_single_block_succes()
{
	const unsigned char test_buf[] = { 0, 1 };
	unsigned nbyte = BLOCK_SIZE;
	unsigned calls = 1;

	mockblockfilter_stub_input(mockblockfilter, RDD_OK, calls);
	mockblockfilter_stub_block(mockblockfilter, RDD_OK, calls);

	CHECK_UINT(RDD_OK, rdd_filter_push(mockblockfilter, test_buf, nbyte));

	const unsigned char **bufs = calloc(calls, sizeof(unsigned char));
	bufs[0] = &test_buf[0];
	unsigned nbytes[] = { 2 };

	CHECK_TRUE(mockblockfilter_verify_input(mockblockfilter, 1, bufs, nbytes));

	CHECK_TRUE(mockblockfilter_verify_block(mockblockfilter, 1, nbytes));

	return 1;
}

static int
test_blockfilter_push_multiple_block_succes()
{
	unsigned calls = 4;
	unsigned char test_buf[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	unsigned nbyte = BLOCK_SIZE * calls;

	mockblockfilter_stub_input(mockblockfilter, RDD_OK, calls);
	mockblockfilter_stub_block(mockblockfilter, RDD_OK, calls);

	CHECK_UINT(RDD_OK, rdd_filter_push(mockblockfilter, test_buf, nbyte));

	const unsigned char **bufs = calloc(calls, sizeof(unsigned char));
	bufs[0] = &test_buf[0];
	bufs[1] = &test_buf[2];
	bufs[2] = &test_buf[4];
	bufs[3] = &test_buf[6];

	unsigned nbytes[] = { 2, 2, 2, 2 };

	CHECK_TRUE(mockblockfilter_verify_input(mockblockfilter, 4, bufs, nbytes));
	CHECK_TRUE(mockblockfilter_verify_block(mockblockfilter, 4, nbytes));

	return 1;
}

static int
test_blockfilter_push_multiple_block_not_even_succes()
{
	unsigned calls = 4;
	unsigned char test_buf[] = { 0, 1, 2, 3, 4, 5, 6 };
	unsigned nbyte = 7;

	mockblockfilter_stub_input(mockblockfilter, RDD_OK, calls);
	mockblockfilter_stub_block(mockblockfilter, RDD_OK, calls);

	CHECK_UINT(RDD_OK, rdd_filter_push(mockblockfilter, test_buf, nbyte));

	const unsigned char **bufs = calloc(4, sizeof(unsigned char));
	bufs[0] = &test_buf[0];
	bufs[1] = &test_buf[2];
	bufs[2] = &test_buf[4];
	bufs[3] = &test_buf[6];

	unsigned input_nbytes[] = { 2, 2, 2, 1 };
	unsigned nbytes[] = { 2, 2, 2 };

	CHECK_TRUE(mockblockfilter_verify_input(mockblockfilter, 4, bufs, input_nbytes));
	CHECK_TRUE(mockblockfilter_verify_block(mockblockfilter, 3, nbytes));

	return 1;
}

static int
test_blockfilter_with_block_residu_close()
{

	unsigned calls = 4;
	unsigned char test_buf[] = { 0, 1, 2, 3, 4, 5, 6 };
	unsigned nbyte = 7;

	mockblockfilter_stub_input(mockblockfilter, RDD_OK, calls);
	mockblockfilter_stub_block(mockblockfilter, RDD_OK, calls);

	CHECK_UINT(RDD_OK, rdd_filter_push(mockblockfilter, test_buf, nbyte));

	mockblockfilter_stub_close(mockblockfilter, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_filter_close(mockblockfilter));

	unsigned nbytes[] = { 2, 2, 2, 1 };
	CHECK_TRUE(mockblockfilter_verify_block(mockblockfilter, 4, nbytes));

	CHECK_TRUE(mockblockfilter_verify_close(mockblockfilter, 1));

	return 1;
}

static int
test_blockfilter_without_block_residu_close()
{
	mockblockfilter_stub_close(mockblockfilter, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_filter_close(mockblockfilter));

	unsigned nbytes[] = { };

	CHECK_TRUE(mockblockfilter_verify_block(mockblockfilter, 0, nbytes));

	CHECK_TRUE(mockblockfilter_verify_close(mockblockfilter, 1));

	return 1;
}

static int
test_streamfilter_close()
{
	mockstreamfilter_stub_close(mockstreamfilter, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_filter_close(mockstreamfilter));

	CHECK_TRUE(mockstreamfilter_verify_close(mockstreamfilter, 1));

	return 1;
}

static int
test_rdd_filter_get_result_empty_buffer()
{

	CHECK_UINT(RDD_BADARG, rdd_filter_get_result(mockstreamfilter,0, 1 ));

	return 1;
}

static int
test_rdd_filter_get_result_blockfilter_error()
{
	unsigned char test_buf[] = {0, 1, 2, 3};

	CHECK_UINT(RDD_NOTFOUND, rdd_filter_get_result(mockblockfilter,test_buf,4 ));

	return 1;
}

static int
test_rdd_filter_get_result_streamfilter_succes()
{
	unsigned char test_buf[] = {0, 1, 2, 3};

	mockstreamfilter_stub_get_result(mockstreamfilter, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_filter_get_result(mockstreamfilter, test_buf, 4));

	mockstreamfilter_verify_get_result(mockstreamfilter, 1);

	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	SAFE_TEST(test_new_filter_self_null);
	TEST(test_new_filter_ops_null);
	TEST(test_new_filter_blockfilter_blocksize_0);
	TEST(test_new_filter_streamfilter_with_blocksize);
	SAFE_TEST(test_streamfilter_push_succes);
	SAFE_TEST(test_blockfilter_push_single_block_succes);
	SAFE_TEST(test_blockfilter_push_multiple_block_succes);
	SAFE_TEST(test_blockfilter_push_multiple_block_not_even_succes);
	SAFE_TEST(test_streamfilter_close);
	SAFE_TEST(test_blockfilter_with_block_residu_close);
	SAFE_TEST(test_blockfilter_without_block_residu_close);
	SAFE_TEST(test_rdd_filter_get_result_empty_buffer);
	SAFE_TEST(test_rdd_filter_get_result_blockfilter_error);
	SAFE_TEST(test_rdd_filter_get_result_streamfilter_succes);

	return result;
}

TEST_MAIN
;
