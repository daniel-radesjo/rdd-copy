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
#include <unistd.h>

#include "rdd.h"
#include "filter.h"
#include "testhelper.h"

#define BLOCK_SIZE 8

static RDD_FILTER *adler_blockfilter, *crc32_blockfilter;

static char adler_path[] = "../test/tadler32_test.txt";
static char crc32_path[] = "../test/tcrc32_test.txt";

static RDD_CHECKSUM_FILE_HEADER *adler32_header, *crc32_header;

typedef struct _CHECKSUM_TEST
{
	uint16_t part1;
	uint16_t part2;
} CHECKSUM_TEST;

static int
test_adler_new_file_header()
{
	FILE *fp;

	CHECK_UINT(RDD_OK, rdd_new_adler32_blockfilter(&adler_blockfilter, BLOCK_SIZE, adler_path, 1));

	CHECK_UINT(RDD_OK, rdd_filter_close(adler_blockfilter));
	CHECK_UINT(RDD_OK, rdd_filter_free(adler_blockfilter));

	CHECK_NOT_NULL(adler32_header = calloc(1, sizeof(*adler32_header)));

	CHECK_NOT_NULL(fp = fopen(adler_path, "r"));
	CHECK_TRUE((fread(adler32_header, sizeof(*adler32_header), 1, fp)) == 1);
	CHECK_TRUE(fclose(fp) == 0);

	CHECK_TRUE(adler32_header->magic == 0xdefd);
	CHECK_TRUE(adler32_header->version == 0x0100);
	CHECK_TRUE(adler32_header->flags == 0x0001);
	CHECK_TRUE(adler32_header->blocksize == 0x0008);
	CHECK_TRUE(adler32_header->imagesize == 0);
	CHECK_TRUE(adler32_header->reserved == 0);
	CHECK_TRUE(adler32_header->offset == 0);

	CHECK_UINT(0, unlink(adler_path));

	return 1;
}

static int
test_crc32_new_file_header()
{
	FILE *fp;

	CHECK_UINT(RDD_OK, rdd_new_crc32_blockfilter(&crc32_blockfilter, BLOCK_SIZE, crc32_path, 1));

	CHECK_UINT(RDD_OK, rdd_filter_close(crc32_blockfilter));
	CHECK_UINT(RDD_OK, rdd_filter_free(crc32_blockfilter));

	CHECK_NOT_NULL(crc32_header = calloc(1, sizeof(*crc32_header)));

	CHECK_NOT_NULL(fp = fopen(crc32_path, "r"));
	CHECK_TRUE((fread(crc32_header, sizeof(*crc32_header), 1, fp)) == 1);
	CHECK_TRUE(fclose(fp) == 0);

	CHECK_TRUE(crc32_header->magic == 0xdefd);
	CHECK_TRUE(crc32_header->version == 0x0100);
	CHECK_TRUE(crc32_header->flags == 0x0002);
	CHECK_TRUE(crc32_header->blocksize == 0x0008);
	CHECK_TRUE(crc32_header->imagesize == 0);
	CHECK_TRUE(crc32_header->reserved == 0);
	CHECK_TRUE(crc32_header->offset == 0);

	CHECK_UINT(0, unlink(crc32_path));

	return 1;
}

static int
test_new_adler_filter_self_null()
{
	CHECK_UINT(RDD_BADARG, rdd_new_adler32_blockfilter(0, BLOCK_SIZE, adler_path, 1));

	return 1;
}

static int
test_new_crc32_filter_self_null()
{
	CHECK_UINT(RDD_BADARG, rdd_new_crc32_blockfilter(0, BLOCK_SIZE, crc32_path, 1));

	return 1;
}

static int
test_new_adler_filter_path_null()
{
	RDD_FILTER *filter;

	CHECK_UINT(RDD_BADARG, rdd_new_adler32_blockfilter(&filter, BLOCK_SIZE, 0, 1));

	return 1;
}

static int
test_new_crc32_filter_path_null()
{
	RDD_FILTER *filter;

	CHECK_UINT(RDD_BADARG, rdd_new_crc32_blockfilter(&filter, BLOCK_SIZE, 0, 1));

	return 1;
}

static int
test_new_adler_filter_blocksize_null()
{
	RDD_FILTER *filter;

	CHECK_UINT(RDD_BADARG, rdd_new_adler32_blockfilter(&filter, 0, adler_path, 1));

	return 1;
}

static int
test_new_crc32_filter_blocksize_null()
{
	RDD_FILTER *filter;

	CHECK_UINT(RDD_BADARG, rdd_new_crc32_blockfilter(&filter, 0, crc32_path, 1));

	return 1;

}

static int
test_adler_checksum()
{
	FILE *fp;
	const unsigned char buf[] = "ujknr_dd";
	unsigned nbyte = 8;
	CHECKSUM_TEST *checksum_test;

	CHECK_UINT(RDD_OK, rdd_new_adler32_blockfilter(&adler_blockfilter, BLOCK_SIZE, adler_path, 1));

	CHECK_UINT(RDD_OK, rdd_filter_push(adler_blockfilter, buf, nbyte));

	CHECK_UINT(RDD_OK, rdd_filter_close(adler_blockfilter));
	CHECK_UINT(RDD_OK, rdd_filter_free(adler_blockfilter));

	CHECK_NOT_NULL(adler32_header = calloc(1, sizeof(*adler32_header)));
	CHECK_NOT_NULL(checksum_test = calloc(1, sizeof(*checksum_test)));

	CHECK_NOT_NULL(fp = fopen(adler_path, "r"));
	CHECK_TRUE((fread(adler32_header, sizeof(*adler32_header), 1, fp)) == 1);
	CHECK_TRUE((fread(checksum_test, sizeof(*checksum_test), 1, fp)) == 1);
	CHECK_TRUE(fclose(fp) == 0);

	CHECK_TRUE(checksum_test->part1 == 0x0352);
	CHECK_TRUE(checksum_test->part2 == 0x0f4f);

	CHECK_UINT(0, unlink(adler_path));

	return 1;
}

static int
test_crc32_checksum()
{
	FILE *fp;
	const unsigned char buf[] = "ujknr_dd";
	unsigned nbyte = 8;
	CHECKSUM_TEST *checksum_test;

	CHECK_UINT(RDD_OK, rdd_new_crc32_blockfilter(&crc32_blockfilter, BLOCK_SIZE, crc32_path, 1));

	CHECK_UINT(RDD_OK, rdd_filter_push(crc32_blockfilter, buf, nbyte));

	CHECK_UINT(RDD_OK, rdd_filter_close(crc32_blockfilter));
	CHECK_UINT(RDD_OK, rdd_filter_free(crc32_blockfilter));

	CHECK_NOT_NULL(crc32_header = calloc(1, sizeof(*crc32_header)));
	CHECK_NOT_NULL(checksum_test = calloc(1, sizeof(*checksum_test)));

	CHECK_NOT_NULL(fp = fopen(crc32_path, "r"));
	CHECK_TRUE((fread(crc32_header, sizeof(*crc32_header), 1, fp)) == 1);
	CHECK_TRUE((fread(checksum_test, sizeof(*checksum_test), 1, fp)) == 1);
	CHECK_TRUE(fclose(fp) == 0);

	CHECK_TRUE(checksum_test->part1 == 0x6ffb);
	CHECK_TRUE(checksum_test->part2 == 0x07fd);

	CHECK_UINT(0, unlink(crc32_path));

	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_adler_new_file_header);
	TEST(test_crc32_new_file_header);
	TEST(test_new_adler_filter_self_null);
	TEST(test_new_crc32_filter_self_null);
	TEST(test_new_adler_filter_path_null);
	TEST(test_new_crc32_filter_path_null);
	TEST(test_new_adler_filter_blocksize_null);
	TEST(test_new_crc32_filter_blocksize_null);
	TEST(test_adler_checksum);
	TEST(test_crc32_checksum);

	return result;
}

TEST_MAIN
;
