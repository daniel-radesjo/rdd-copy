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
#include "sha512streamfilter.c"

#include "testhelper.h"

static int test_new_sha512_streamfilter_null()
{
	CHECK_UINT(RDD_BADARG, rdd_new_sha512_streamfilter(0));
	return 1;
}

static int test_sha512_input_length_0()
{
	unsigned char result[SHA512_DIGEST_LENGTH];
	unsigned char expected_result[] = {0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha512_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha512_input(f, 0, 0));

	CHECK_UINT(RDD_OK, sha512_close(f));

	CHECK_UINT(RDD_OK, sha512_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha512_one_input()
{
	unsigned char result[SHA512_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0xa3, 0xa8, 0xc8, 0x1b, 0xc9, 0x7c, 0x25, 0x60, 0x01, 0x0d, 0x73, 0x89, 0xbc, 0x88, 0xaa, 0xc9, 0x74, 0xa1, 0x04, 0xe0, 0xe2, 0x38, 0x12, 0x20, 0xc6, 0xe0, 0x84, 0xc4, 0xdc, 0xcd, 0x1d, 0x2d, 0x17, 0xd4, 0xf8, 0x6d, 0xb3, 0x1c, 0x2a, 0x85, 0x1d, 0xc8, 0x0e, 0x66, 0x81, 0xd7, 0x47, 0x33, 0xc5, 0x5d, 0xcd, 0x03, 0xdd, 0x96, 0xf6, 0x06, 0x2c, 0xdd, 0xa1, 0x2a, 0x29, 0x1a, 0xe6, 0xce};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha512_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha512_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha512_close(f));

	CHECK_UINT(RDD_OK, sha512_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha512_multiple_inputs()
{
	unsigned char result[SHA512_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0x23, 0xd2, 0xd2, 0x8e, 0xdf, 0xb7, 0x6b, 0xe1, 0x83, 0x36, 0xcc, 0x1f, 0xcb, 0xc4, 0x75, 0x51, 0xa0, 0xa6, 0xdc, 0x3f, 0xf3, 0x73, 0x2a, 0x76, 0x38, 0xab, 0x3e, 0x3e, 0xa3, 0xb9, 0x7d, 0xb6, 0x23, 0x6d, 0xf6, 0xda, 0x6c, 0x31, 0x64, 0xcf, 0xd9, 0x96, 0x35, 0xb0, 0x26, 0xa8, 0x1c, 0x60, 0xef, 0x88, 0x9c, 0x25, 0x4b, 0xa7, 0x3e, 0xa1, 0xd0, 0xd5, 0x40, 0x68, 0x19, 0x87, 0xea, 0x9d};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha512_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha512_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, sha512_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, sha512_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha512_close(f));

	CHECK_UINT(RDD_OK, sha512_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha512_close_null()
{
	CHECK_UINT(RDD_BADARG, sha512_close(0));
	return 1;
}

static int test_sha512_get_result_null()
{
	unsigned char result[SHA512_DIGEST_LENGTH];

	CHECK_UINT(RDD_BADARG, sha512_get_result(0, result, sizeof(result)));

	return 1;
}

static int test_sha512_get_result_without_close()
{
	unsigned char result[SHA512_DIGEST_LENGTH];
	unsigned char expected_result[SHA512_DIGEST_LENGTH];

	int i;
	for (i=0; i<SHA512_DIGEST_LENGTH; i++) {
		expected_result[i] = 0;
	}

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha512_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha512_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_sha512_get_result_buffer_too_small()
{
	unsigned char result[SHA512_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha512_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha512_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha512_close(f));

	CHECK_UINT(RDD_ESPACE, sha512_get_result(f, result, sizeof(result)-1));


	return 1;
}

static int test_sha512_get_result_buffer_too_large()
{
	unsigned char result[SHA512_DIGEST_LENGTH+1];

	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0xa3, 0xa8, 0xc8, 0x1b, 0xc9, 0x7c, 0x25, 0x60, 0x01, 0x0d, 0x73, 0x89, 0xbc, 0x88, 0xaa, 0xc9, 0x74, 0xa1, 0x04, 0xe0, 0xe2, 0x38, 0x12, 0x20, 0xc6, 0xe0, 0x84, 0xc4, 0xdc, 0xcd, 0x1d, 0x2d, 0x17, 0xd4, 0xf8, 0x6d, 0xb3, 0x1c, 0x2a, 0x85, 0x1d, 0xc8, 0x0e, 0x66, 0x81, 0xd7, 0x47, 0x33, 0xc5, 0x5d, 0xcd, 0x03, 0xdd, 0x96, 0xf6, 0x06, 0x2c, 0xdd, 0xa1, 0x2a, 0x29, 0x1a, 0xe6, 0xce, 0x5e};

	result[SHA512_DIGEST_LENGTH] = 0x5e;

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_sha512_streamfilter(&f));

	CHECK_UINT(RDD_OK, sha512_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, sha512_close(f));

	CHECK_UINT(RDD_OK, sha512_get_result(f, result, sizeof(result)));
	/* Larger buffer is not a problem; no mods should occur beyond hash */

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));


	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_new_sha512_streamfilter_null);
	TEST(test_sha512_input_length_0);
	TEST(test_sha512_one_input);
	TEST(test_sha512_multiple_inputs);
	TEST(test_sha512_close_null);
	TEST(test_sha512_get_result_null);
	TEST(test_sha512_get_result_without_close);
	TEST(test_sha512_get_result_buffer_too_small);
	TEST(test_sha512_get_result_buffer_too_large);

	return result;
}

TEST_MAIN;