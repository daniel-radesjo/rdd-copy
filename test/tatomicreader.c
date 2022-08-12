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
#include "reader.h"
#include "mockreader.h"

#include "testhelper.h"

static RDD_READER *mock_reader, *atomic_reader;

static int
setup()
{
	CHECK_UINT(RDD_OK, mockreader_open(&mock_reader));
	CHECK_UINT(RDD_OK, rdd_open_atomic_reader(&atomic_reader, mock_reader));

	return 1;
}

static int
teardown()
{
	mock_reader = NULL;

	if (atomic_reader != NULL)
	{
		CHECK_UINT(RDD_OK, rdd_reader_close(atomic_reader, 0));
		atomic_reader = NULL;
	}

	return 1;
}

static int
test_open_atomic_reader_parent_reader_null()
{
	CHECK_UINT(RDD_BADARG, rdd_open_atomic_reader(&atomic_reader, NULL));
	return 1;
}

static int
test_atomic_read_success()
{
	unsigned char test_buf[7] = { 0, 1, 2, 3, 4, 5, 6 };
	unsigned char buf[7];
	unsigned nread;

	mockreader_stub_tell(mock_reader, 42, RDD_OK);

	mockreader_stub_read(mock_reader, test_buf, 7, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_reader_read(atomic_reader, buf, 7, &nread));

	CHECK_TRUE(mockreader_verify_tell(mock_reader, 1));
	CHECK_TRUE(mockreader_verify_read(mock_reader, 1, 7, 7));

	return 1;
}

static int
test_atomic_read_succes_small_buffer()
{
	unsigned char test_buf[7] = { 0, 1, 2, 3, 4, 5, 6 };
	unsigned char buf[7];
	unsigned nread;

	mockreader_stub_tell(mock_reader, 42, RDD_OK);

	mockreader_stub_read(mock_reader, test_buf, 7, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_reader_read(atomic_reader, buf, 14, &nread));

	CHECK_TRUE(mockreader_verify_tell(mock_reader, 1));
	CHECK_TRUE(mockreader_verify_read(mock_reader, 1, 14, 7));

	return 1;
}

static int
test_atomic_read_failed()
{
	unsigned char test_buf[7] = { 0, 1, 2, 3, 4, 5, 6 };
	unsigned char buf[7];
	unsigned nread;

	mockreader_stub_tell(mock_reader, 42, RDD_OK);

	mockreader_stub_read(mock_reader, test_buf, 7, RDD_EREAD);

	mockreader_stub_seek(mock_reader, RDD_OK);

	CHECK_UINT(RDD_EREAD, rdd_reader_read(atomic_reader, buf, 7, &nread));

	CHECK_TRUE(mockreader_verify_tell(mock_reader, 1));
	CHECK_TRUE(mockreader_verify_seek(mock_reader, 1, 42));

	return 1;
}

static int
test_atomic_read_save_position_failed()
{
	unsigned char buf[7];
	unsigned nread;

	mockreader_stub_tell(mock_reader, 42, RDD_ETELL);

	CHECK_UINT(RDD_ETELL, rdd_reader_read(atomic_reader, buf, 7, &nread));

	return 1;
}

static int
test_atomic_read_restore_position_failed()
{
	unsigned char test_buf[7] = { 0, 1, 2, 3, 4, 5, 6 };
	unsigned char buf[7];
	unsigned nread;

	mockreader_stub_tell(mock_reader, 42, RDD_OK);
	mockreader_stub_read(mock_reader, test_buf, 7, RDD_EREAD);
	mockreader_stub_seek(mock_reader, RDD_ESEEK);

	CHECK_UINT(RDD_ESEEK, rdd_reader_read(atomic_reader, buf, 7, &nread));

	CHECK_TRUE(mockreader_verify_tell(mock_reader, 1));
	CHECK_TRUE(mockreader_verify_seek(mock_reader, 1, 42));

	return 1;
}

static int
test_atomic_tell_success()
{
	rdd_count_t pos;

	mockreader_stub_tell(mock_reader, 42, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_reader_tell(atomic_reader,&pos ));

	CHECK_UINT(42, pos);

	CHECK_TRUE(mockreader_verify_tell(mock_reader, 1));

	return 1;
}

static int
test_atomic_tell_fail()
{
	rdd_count_t pos;

	mockreader_stub_tell(mock_reader, 42, RDD_ETELL);

	CHECK_UINT(RDD_ETELL, rdd_reader_tell(atomic_reader,&pos ));

	return 1;
}

static int
test_atomic_seek_success()
{
	mockreader_stub_seek(mock_reader, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_reader_seek(atomic_reader, 42 ));

	CHECK_TRUE(mockreader_verify_seek(mock_reader,1, 42));

	return 1;
}

static int
test_atomic_seek_fail()
{
	mockreader_stub_seek(mock_reader, RDD_ESEEK);

	CHECK_UINT(RDD_ESEEK, rdd_reader_seek(atomic_reader, 42 ));

	return 1;
}

static int
test_atomic_close_success_with_recurse()
{
	mockreader_stub_close(mock_reader, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_reader_close(atomic_reader, 1));

	// cannot verify, the atomic_reader has destroyed OUR state!!!! :-((((
	//CHECK_TRUE(verify_mock_reader_close(mock_reader, 1, 1));
	atomic_reader = NULL;

	return 1;
}

static int
test_atomic_close_success_no_recurse()
{
	mockreader_stub_close(mock_reader, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_reader_close(atomic_reader, 0));

	atomic_reader = NULL;

	CHECK_TRUE(mockreader_verify_close(mock_reader,0, 1));

	return 1;
}

static int
test_atomic_close_fail_no_recurse()
{
	mockreader_stub_close(mock_reader, RDD_ECLOSE);

	CHECK_UINT(RDD_OK, rdd_reader_close(atomic_reader, 0));
	atomic_reader = NULL;

	CHECK_TRUE(mockreader_verify_close(mock_reader, 0, 0));

	return 1;
}

static int
test_atomic_close_fail_with_recurse()
{
	mockreader_stub_close(mock_reader, RDD_ECLOSE);

	CHECK_UINT(RDD_ECLOSE, rdd_reader_close(atomic_reader, 1));

	CHECK_TRUE(mockreader_verify_close(mock_reader, 1, 1));

	return 1;
}

static int
call_tests(void)
{
	int result = 1;
	TEST(test_open_atomic_reader_parent_reader_null);
	SAFE_TEST(test_atomic_read_success);
	SAFE_TEST(test_atomic_read_succes_small_buffer);
	SAFE_TEST(test_atomic_read_failed);
	SAFE_TEST(test_atomic_read_save_position_failed);
	SAFE_TEST(test_atomic_read_restore_position_failed);
	SAFE_TEST(test_atomic_tell_success);
	SAFE_TEST(test_atomic_tell_fail);
	SAFE_TEST(test_atomic_seek_success);
	SAFE_TEST(test_atomic_seek_fail);
	SAFE_TEST(test_atomic_close_success_with_recurse);
	SAFE_TEST(test_atomic_close_success_no_recurse);
	SAFE_TEST(test_atomic_close_fail_no_recurse);
	SAFE_TEST(test_atomic_close_fail_with_recurse);

	return result;
}

TEST_MAIN
;

