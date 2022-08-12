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
#include "md5streamfilter.c"

#include "testhelper.h"

static int test_new_md5_streamfilter_null()
{
	CHECK_UINT(RDD_BADARG, rdd_new_md5_streamfilter(0));
	return 1;
}

static int test_md5_input_length_0()
{
	unsigned char result[MD5_DIGEST_LENGTH];
	unsigned char expected_result[] = {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_md5_streamfilter(&f));

	CHECK_UINT(RDD_OK, md5_input(f, 0, 0));

	CHECK_UINT(RDD_OK, md5_close(f));

	CHECK_UINT(RDD_OK, md5_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_md5_one_input()
{
	unsigned char result[MD5_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0xe8, 0xdc, 0x40, 0x81, 0xb1, 0x34, 0x34, 0xb4, 0x51, 0x89, 0xa7, 0x20, 0xb7, 0x7b, 0x68, 0x18};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_md5_streamfilter(&f));

	CHECK_UINT(RDD_OK, md5_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, md5_close(f));

	CHECK_UINT(RDD_OK, md5_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_md5_multiple_inputs()
{
	unsigned char result[MD5_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0xf6, 0x13, 0xa6, 0xf6, 0x94, 0xb6, 0xdc, 0x12, 0xda, 0x59, 0x8a, 0x07, 0xa8, 0x2b, 0xa6, 0x66};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_md5_streamfilter(&f));

	CHECK_UINT(RDD_OK, md5_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, md5_input(f, input, sizeof(input)));
	CHECK_UINT(RDD_OK, md5_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, md5_close(f));

	CHECK_UINT(RDD_OK, md5_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_md5_close_null()
{
	CHECK_UINT(RDD_BADARG, md5_close(0));
	return 1;
}

static int test_md5_get_result_null()
{
	unsigned char result[MD5_DIGEST_LENGTH];

	CHECK_UINT(RDD_BADARG, md5_get_result(0, result, sizeof(result)));

	return 1;
}

static int test_md5_get_result_without_close()
{
	unsigned char result[MD5_DIGEST_LENGTH];
	unsigned char expected_result[MD5_DIGEST_LENGTH];

	int i;
	for (i=0; i<MD5_DIGEST_LENGTH; i++) {
		expected_result[i] = 0;
	}

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_md5_streamfilter(&f));

	CHECK_UINT(RDD_OK, md5_get_result(f, result, sizeof(result)));

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));

	return 1;
}

static int test_md5_get_result_buffer_too_small()
{
	unsigned char result[MD5_DIGEST_LENGTH];
	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_md5_streamfilter(&f));

	CHECK_UINT(RDD_OK, md5_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, md5_close(f));

	CHECK_UINT(RDD_ESPACE, md5_get_result(f, result, sizeof(result)-1));


	return 1;
}

static int test_md5_get_result_buffer_too_large()
{
	unsigned char result[MD5_DIGEST_LENGTH+1];

	unsigned char input[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char expected_result[] = {0xe8, 0xdc, 0x40, 0x81, 0xb1, 0x34, 0x34, 0xb4, 0x51, 0x89, 0xa7, 0x20, 0xb7, 0x7b, 0x68, 0x18, 0x5e};

	result[MD5_DIGEST_LENGTH] = 0x5e;

	RDD_FILTER *f;

	CHECK_UINT(RDD_OK, rdd_new_md5_streamfilter(&f));

	CHECK_UINT(RDD_OK, md5_input(f, input, sizeof(input)));

	CHECK_UINT(RDD_OK, md5_close(f));

	CHECK_UINT(RDD_OK, md5_get_result(f, result, sizeof(result)));
	/* Larger buffer is not a problem; no mods should occur beyond hash */

	CHECK_UCHAR_ARRAY(expected_result, result, sizeof(result));


	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_new_md5_streamfilter_null);
	TEST(test_md5_input_length_0);
	TEST(test_md5_one_input);
	TEST(test_md5_multiple_inputs);
	TEST(test_md5_close_null);
	TEST(test_md5_get_result_null);
	TEST(test_md5_get_result_without_close);
	TEST(test_md5_get_result_buffer_too_small);
	TEST(test_md5_get_result_buffer_too_large);
	
	return result;
}

TEST_MAIN;
