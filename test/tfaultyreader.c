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

/* A unit-test for the faultyreader.c.
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
#include "mockreader.h"
#include "faultyreader.c"

#include "testhelper.h"

static RDD_READER *mockreader, *faultyreader;

static char path[] = "../test/simfile.txt";

static char maxline_testfile[] = "../test/faultyreader_t1.txt";
static char itemcount_testfile[] = "../test/faultyreader_t2.txt";
static char longline_testfile[] = "../test/faultyreader_t3.txt";

static int
setup()
{
	CHECK_UINT(RDD_OK, mockreader_open(&mockreader));
	CHECK_UINT(RDD_OK, rdd_open_faulty_reader(&faultyreader, mockreader, path));

	return 1;
}

static int
teardown()
{
	mockreader = NULL;

	if (faultyreader != NULL)
	{
		CHECK_UINT(RDD_OK, rdd_reader_close(faultyreader, 0));
		faultyreader = NULL;
	}

	return 1;
}

static int
test_open_faulty_reader_self_null()
{
	CHECK_UINT(RDD_BADARG, rdd_open_faulty_reader(0, mockreader,path ));

	return 1;
}

static int
test_open_faulty_reader_parent_null()
{
	RDD_READER *reader;
	CHECK_UINT(RDD_BADARG, rdd_open_faulty_reader(&reader, 0, path));

	return 1;
}

static int
test_open_faulty_reader_file_null()
{
	RDD_READER *reader;

	CHECK_UINT(RDD_BADARG,rdd_open_faulty_reader(&reader, mockreader, NULL));

	return 1;
}

static int
test_faulty_reader_too_many_lines()
{
	RDD_READER *reader;

	CHECK_UINT(RDD_ESPACE, rdd_open_faulty_reader(&reader, mockreader, maxline_testfile));

	return 1;
}

static int
test_faulty_reader_bad_item_count()
{
	RDD_READER *reader;

	CHECK_UINT(RDD_ESYNTAX, rdd_open_faulty_reader(&reader, mockreader, itemcount_testfile));

	return 1;
}

static int
test_faulty_reader_line_to_long()
{
	RDD_READER *reader;

	CHECK_UINT(RDD_ESYNTAX, rdd_open_faulty_reader(&reader, mockreader, longline_testfile));

	return 1;
}

static int
test_faulty_reader_read_parent_tell_error()
{
	unsigned char buf[7];
	unsigned nread;

	mockreader_stub_tell(mockreader, 1, RDD_ETELL);

	CHECK_UINT(RDD_ETELL, rdd_faulty_read(faultyreader,buf, 7, &nread ));

	CHECK_TRUE(mockreader_verify_tell(mockreader, 1));

	return 1;
}

static int
test_faulty_reader_read_true_read_error()
{
	unsigned char read_buf[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	unsigned read_buf_size = 8;

	unsigned char buf[8];
	unsigned nread;

	mockreader_stub_tell(mockreader, 0, RDD_OK);
	mockreader_stub_read(mockreader, read_buf, read_buf_size, RDD_EREAD);

	CHECK_UINT(RDD_EREAD, rdd_faulty_read(faultyreader, buf, 8, &nread));

	CHECK_TRUE(mockreader_verify_tell(mockreader, 1));
	CHECK_TRUE(mockreader_verify_read(mockreader, 1, 8, 8));

	return 1;
}

static int
test_faulty_reader_read_read_forward()
{
	unsigned char read_buf[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	unsigned read_buf_size = 8;

	unsigned char buf[8];
	unsigned nread;

	mockreader_stub_tell(mockreader, 0, RDD_OK);
	mockreader_stub_read(mockreader, read_buf, read_buf_size, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_faulty_read(faultyreader, buf, 2, &nread));

	CHECK_TRUE(mockreader_verify_tell(mockreader, 1));
	CHECK_TRUE(mockreader_verify_read(mockreader, 1, 2, 2));

	return 1;
}

static int
test_faulty_reader_read_fault_after_nread()
{
	unsigned char read_buf[] = { 0, 1 };
	unsigned read_buf_size = 2;

	unsigned char buf[8];
	unsigned nread;

	mockreader_stub_tell(mockreader, 0, RDD_OK);
	mockreader_stub_read(mockreader, read_buf, read_buf_size, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_faulty_read(faultyreader, buf, 8, &nread));

	CHECK_TRUE(mockreader_verify_tell(mockreader, 1));
	CHECK_TRUE(mockreader_verify_read(mockreader, 1, 8, 2));

	return 1;

}

static int
test_faulty_reader_read_simulated_fault()
{
	unsigned char read_buf[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	unsigned read_buf_size = 8;

	unsigned char buf[8];
	unsigned nread;

	mockreader_stub_tell(mockreader, 0, RDD_OK);
	mockreader_stub_read(mockreader, read_buf, read_buf_size, RDD_OK);

	CHECK_UINT(RDD_EREAD, rdd_faulty_read(faultyreader, buf, 8, &nread));

	CHECK_TRUE(mockreader_verify_tell(mockreader, 1));
	CHECK_TRUE(mockreader_verify_read(mockreader, 1, 8, 8));

	return 1;

}

static int
test_faulty_tell()
{
	rdd_count_t pos;
	mockreader_stub_tell(mockreader, 8, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_faulty_tell(faultyreader, &pos));

	CHECK_UINT(8, pos);

	CHECK_TRUE(mockreader_verify_tell(mockreader, 1));
	return 1;
}

static int
test_faulty_read_tell_error()
{
	unsigned char buf[7];
	unsigned nread;

	mockreader_stub_tell(mockreader, 0, RDD_ETELL);

	CHECK_UINT(RDD_ETELL, rdd_faulty_read(faultyreader,buf, 7, &nread));

	CHECK_TRUE(mockreader_verify_tell(mockreader, 1));

	return 1;
}

static int
test_faulty_seek()
{
	mockreader_stub_seek(mockreader, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_faulty_seek(faultyreader, 42));

	CHECK_TRUE(mockreader_verify_seek(mockreader, 1, 42));

	return 1;
}

static int
test_faulty_close()
{
	mockreader_stub_close(mockreader, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_faulty_close(faultyreader, 0));

	CHECK_TRUE(mockreader_verify_close(mockreader,0, 0));

	return 1;
}

static int
test_faulty_close_recurse()
{
	mockreader_stub_close(mockreader, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_faulty_close(faultyreader, 1));

	// cannot verify, the faultyreader has destroyed OUR state!! :-((
	//CHECK_TRUE(mockreader_verify_close(mockreader, 1, 1));
	faultyreader = NULL;

	return 1;
}

static int
test_faulty_close_recurse_failed()
{
	mockreader_stub_close(mockreader, RDD_ECLOSE);

	CHECK_UINT(RDD_ECLOSE, rdd_faulty_close(faultyreader, 1));

	CHECK_TRUE(mockreader_verify_close(mockreader, 1, 1));

	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	SAFE_TEST(test_open_faulty_reader_self_null);
	SAFE_TEST(test_open_faulty_reader_parent_null);
	SAFE_TEST(test_open_faulty_reader_file_null);
	SAFE_TEST(test_faulty_reader_too_many_lines);
	SAFE_TEST(test_faulty_reader_bad_item_count);
	SAFE_TEST(test_faulty_reader_line_to_long);
	SAFE_TEST(test_faulty_reader_read_parent_tell_error);
	SAFE_TEST(test_faulty_reader_read_true_read_error);
	SAFE_TEST(test_faulty_reader_read_read_forward);
	SAFE_TEST(test_faulty_reader_read_fault_after_nread);
	SAFE_TEST(test_faulty_reader_read_simulated_fault);

	SAFE_TEST(test_faulty_tell);
	SAFE_TEST(test_faulty_read_tell_error);
	SAFE_TEST(test_faulty_seek);
	SAFE_TEST(test_faulty_close);
	SAFE_TEST(test_faulty_close_recurse);
	SAFE_TEST(test_faulty_close_recurse_failed);

	return result;
}

TEST_MAIN
;
