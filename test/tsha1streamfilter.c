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
#include "sha1streamfilter.c"

#include "testhelper.h"

static int test_new_sha1_streamfilter_null()
{
	CHECK_UINT(RDD_BADARG, rdd_new_sha1_streamfilter(0));
	return 1;
}

static int test_sha1_input_length_0()
{
	unsigned char result[SHA_DIGEST_LENGTH];
	unsigned char expected_result[] = {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha1_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha1_input(f, 0, 0));

	CHECK_UINT(RDD_OK, sha1_close(f));

	CHECK_UINT(RDD_OK, sha1_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha1_one_input()
{
	unsigned char result[SHA_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x42, 0x5a, 0xf1, 0x2a, 0x07, 0x43, 0x50, 0x2b, 0x32, 0x2e, 0x93, 0xa0, 0x15, 0xbc, 0xf8, 0x68, 0xe3, 0x24, 0xd5, 0x6a};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha1_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha1_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha1_close(f));

	CHECK_UINT(RDD_OK, sha1_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha1_multiple_inputs()
{
	unsigned char result[SHA_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x4d, 0xae, 0x44, 0xa5, 0x1b, 0x9e, 0xbe, 0x61, 0x04, 0x37, 0x2f, 0x96, 0x46, 0xd2, 0x54, 0x75, 0x9c, 0xea, 0xed, 0x3b};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha1_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha1_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, sha1_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, sha1_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha1_close(f));

	CHECK_UINT(RDD_OK, sha1_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha1_close_null()
{
	CHECK_UINT(RDD_BADARG, sha1_close(0));
	return 1;
}

static int test_sha1_get_result_null()
{
	unsigned char result[SHA_DIGEST_LENGTH];

	CHECK_UINT(RDD_BADARG, sha1_get_result(0, result, sizeof(result)));

	return 1;
}

static int test_sha1_get_result_without_close()
{
	unsigned char result[SHA_DIGEST_LENGTH];
	unsigned char expected_result[SHA_DIGEST_LENGTH];

	int i;
	for (i=0; i<SHA_DIGEST_LENGTH; i++) {
		expected_result[i] = 0;
	}

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha1_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha1_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha1_get_result_buffer_too_small()
{
	unsigned char result[SHA_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha1_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha1_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha1_close(f));

	CHECK_UINT(RDD_ESPACE, sha1_get_result(f, result, sizeof(result)-1));


	return 1;
}

static int test_sha1_get_result_buffer_too_large()
{
	unsigned char result[SHA_DIGEST_LENGTH+1];

	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x42, 0x5a, 0xf1, 0x2a, 0x07, 0x43, 0x50, 0x2b, 0x32, 0x2e, 0x93, 0xa0, 0x15, 0xbc, 0xf8, 0x68, 0xe3, 0x24, 0xd5, 0x6a, 0x5e};

	result[SHA_DIGEST_LENGTH] = 0x5e;

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha1_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha1_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha1_close(f));

	CHECK_UINT(RDD_OK, sha1_get_result(f, result, sizeof(result)));
	/* Larger buffer is not a problem; no mods should occur beyond hash */

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));


	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_new_sha1_streamfilter_null);
	TEST(test_sha1_input_length_0);
	TEST(test_sha1_one_input);
	TEST(test_sha1_multiple_inputs);
	TEST(test_sha1_close_null);
	TEST(test_sha1_get_result_null);
	TEST(test_sha1_get_result_without_close);
	TEST(test_sha1_get_result_buffer_too_small);
	TEST(test_sha1_get_result_buffer_too_large);

	return result;
}

TEST_MAIN;
