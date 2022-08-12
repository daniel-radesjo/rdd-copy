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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>



#include "rdd.h"
#include "sha256streamfilter.c"

#include "testhelper.h"

static int test_new_sha256_streamfilter_null()
{
	CHECK_UINT(RDD_BADARG, rdd_new_sha256_streamfilter(0));
	return 1;
}

static int test_sha256_input_length_0()
{
	unsigned char result[SHA256_DIGEST_LENGTH];
	unsigned char expected_result[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha256_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha256_input(f, 0, 0));

	CHECK_UINT(RDD_OK, sha256_close(f));

	CHECK_UINT(RDD_OK, sha256_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha256_one_input()
{
	unsigned char result[SHA256_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x9c, 0x56, 0xcc, 0x51, 0xb3, 0x74, 0xc3, 0xba, 0x18, 0x92, 0x10, 0xd5, 0xb6, 0xd4, 0xbf, 0x57, 0x79, 0x0d, 0x35, 0x1c, 0x96, 0xc4, 0x7c, 0x02, 0x19, 0x0e, 0xcf, 0x1e, 0x43, 0x06, 0x35, 0xab};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha256_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha256_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha256_close(f));

	CHECK_UINT(RDD_OK, sha256_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha256_multiple_inputs()
{
	unsigned char result[SHA256_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x6b, 0x12, 0xa0, 0x0f, 0x82, 0x41, 0x7b, 0x74, 0x36, 0x7a, 0x37, 0xfe, 0x52, 0x88, 0x50, 0x28, 0xe7, 0xff, 0xac, 0xd0, 0x86, 0x5a, 0xbd, 0x99, 0x1b, 0xd3, 0x3e, 0x75, 0x93, 0x68, 0xdb, 0xe2};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha256_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha256_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, sha256_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, sha256_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha256_close(f));

	CHECK_UINT(RDD_OK, sha256_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha256_close_null()
{
	CHECK_UINT(RDD_BADARG, sha256_close(0));
	return 1;
}

static int test_sha256_get_result_null()
{
	unsigned char result[SHA256_DIGEST_LENGTH];

	CHECK_UINT(RDD_BADARG, sha256_get_result(0, result, sizeof(result)));

	return 1;
}

static int test_sha256_get_result_without_close()
{
	unsigned char result[SHA256_DIGEST_LENGTH];
	unsigned char expected_result[SHA256_DIGEST_LENGTH];

	int i;
	for (i=0; i<SHA256_DIGEST_LENGTH; i++) {
		expected_result[i] = 0;
	}

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha256_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha256_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha256_get_result_buffer_too_small()
{
	unsigned char result[SHA256_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha256_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha256_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha256_close(f));

	CHECK_UINT(RDD_ESPACE, sha256_get_result(f, result, sizeof(result)-1));


	return 1;
}

static int test_sha256_get_result_buffer_too_large()
{
	unsigned char result[SHA256_DIGEST_LENGTH+1];

	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x9c, 0x56, 0xcc, 0x51, 0xb3, 0x74, 0xc3, 0xba, 0x18, 0x92, 0x10, 0xd5, 0xb6, 0xd4, 0xbf, 0x57, 0x79, 0x0d, 0x35, 0x1c, 0x96, 0xc4, 0x7c, 0x02, 0x19, 0x0e, 0xcf, 0x1e, 0x43, 0x06, 0x35, 0xab, 0x5e};

	result[SHA256_DIGEST_LENGTH] = 0x5e;

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha256_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha256_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha256_close(f));

	CHECK_UINT(RDD_OK, sha256_get_result(f, result, sizeof(result)));
	/* Larger buffer is not a problem; no mods should occur beyond hash */

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));


	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_new_sha256_streamfilter_null);
	TEST(test_sha256_input_length_0);
	TEST(test_sha256_one_input);
	TEST(test_sha256_multiple_inputs);
	TEST(test_sha256_close_null);
	TEST(test_sha256_get_result_null);
	TEST(test_sha256_get_result_without_close);
	TEST(test_sha256_get_result_buffer_too_small);
	TEST(test_sha256_get_result_buffer_too_large);

	return result;
}

TEST_MAIN;
