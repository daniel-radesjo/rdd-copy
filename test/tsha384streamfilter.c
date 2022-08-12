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
#include "sha384streamfilter.c"

#include "testhelper.h"

static int test_new_sha384_streamfilter_null()
{
	CHECK_UINT(RDD_BADARG, rdd_new_sha384_streamfilter(0));
	return 1;
}

static int test_sha384_input_length_0()
{
	unsigned char result[SHA384_DIGEST_LENGTH];
	unsigned char expected_result[] = {0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha384_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha384_input(f, 0, 0));

	CHECK_UINT(RDD_OK, sha384_close(f));

	CHECK_UINT(RDD_OK, sha384_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha384_one_input()
{
	unsigned char result[SHA384_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x90, 0x00, 0xcd, 0x7c, 0xad, 0xa5, 0x9d, 0x1d, 0x2e, 0xb8, 0x29, 0x12, 0xf7, 0xf2, 0x4e, 0x5e, 0x69, 0xcc, 0x55, 0x17, 0xf6, 0x82, 0x83, 0xb0, 0x05, 0xfa, 0x27, 0xc2, 0x85, 0xb6, 0x1e, 0x05, 0xed, 0xf1, 0xad, 0x1a, 0x8a, 0x9b, 0xde, 0xd6, 0xfd, 0x29, 0xeb, 0x87, 0xd7, 0x5a, 0xd8, 0x06};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha384_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha384_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha384_close(f));

	CHECK_UINT(RDD_OK, sha384_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha384_multiple_inputs()
{
	unsigned char result[SHA384_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x27, 0x43, 0xe9, 0x25, 0xa8, 0x28, 0x7a, 0xbd, 0xa9, 0xf9, 0x1e, 0x61, 0xca, 0xd1, 0xad, 0x3f, 0x62, 0x44, 0x69, 0x30, 0x1f, 0x41, 0x26, 0x58, 0x89, 0xb3, 0x03, 0xbe, 0xc4, 0x33, 0x56, 0x0e, 0x22, 0x0b, 0x0c, 0x19, 0x0e, 0xb9, 0xc6, 0x88, 0x0a, 0x1f, 0xf3, 0x87, 0xcd, 0x5f, 0x8c, 0xa2};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha384_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha384_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, sha384_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, sha384_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha384_close(f));

	CHECK_UINT(RDD_OK, sha384_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha384_close_null()
{
	CHECK_UINT(RDD_BADARG, sha384_close(0));
	return 1;
}

static int test_sha384_get_result_null()
{
	unsigned char result[SHA384_DIGEST_LENGTH];

	CHECK_UINT(RDD_BADARG, sha384_get_result(0, result, sizeof(result)));

	return 1;
}

static int test_sha384_get_result_without_close()
{
	unsigned char result[SHA384_DIGEST_LENGTH];
	unsigned char expected_result[SHA384_DIGEST_LENGTH];

	int i;
	for (i=0; i<SHA384_DIGEST_LENGTH; i++) {
		expected_result[i] = 0;
	}

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha384_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha384_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha384_get_result_buffer_too_small()
{
	unsigned char result[SHA384_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha384_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha384_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha384_close(f));

	CHECK_UINT(RDD_ESPACE, sha384_get_result(f, result, sizeof(result)-1));


	return 1;
}

static int test_sha384_get_result_buffer_too_large()
{
	unsigned char result[SHA384_DIGEST_LENGTH+1];

	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x90, 0x00, 0xcd, 0x7c, 0xad, 0xa5, 0x9d, 0x1d, 0x2e, 0xb8, 0x29, 0x12, 0xf7, 0xf2, 0x4e, 0x5e, 0x69, 0xcc, 0x55, 0x17, 0xf6, 0x82, 0x83, 0xb0, 0x05, 0xfa, 0x27, 0xc2, 0x85, 0xb6, 0x1e, 0x05, 0xed, 0xf1, 0xad, 0x1a, 0x8a, 0x9b, 0xde, 0xd6, 0xfd, 0x29, 0xeb, 0x87, 0xd7, 0x5a, 0xd8, 0x06, 0x5e};

	result[SHA384_DIGEST_LENGTH] = 0x5e;

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha384_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha384_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha384_close(f));

	CHECK_UINT(RDD_OK, sha384_get_result(f, result, sizeof(result)));
	/* Larger buffer is not a problem; no mods should occur beyond hash */

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));


	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_new_sha384_streamfilter_null);
	TEST(test_sha384_input_length_0);
	TEST(test_sha384_one_input);
	TEST(test_sha384_multiple_inputs);
	TEST(test_sha384_close_null);
	TEST(test_sha384_get_result_null);
	TEST(test_sha384_get_result_without_close);
	TEST(test_sha384_get_result_buffer_too_small);
	TEST(test_sha384_get_result_buffer_too_large);

	return result;
}

TEST_MAIN;

