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


/* A unit-test for the tcp writer. This file replaces the original ttcpwriter.c file, which is now called tpython_tcpwriter.c.
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
#include "safewriter.c"

#include "testhelper.h"

static int 
test_open_safe_writer_writer_null()
{
	CHECK_UINT(RDD_BADARG, rdd_open_safe_writer(0, "path", 0));
	return 1;
}

static int 
test_open_safe_writer_path_null()
{
	RDD_WRITER * writer;
	CHECK_UINT(RDD_BADARG, rdd_open_safe_writer(&writer, 0, 0));
	return 1;
}

static int 
test_open_safe_writer()
{
	RDD_WRITER * writer = 0;

	const char * FILE_LIST[] = {
			"newfile"
	};
	const int NUM_FILES = 1;

	IGNORE_RESULT(deleteFiles(FILE_LIST, NUM_FILES));	
	
	CHECK_UINT_GOTO(RDD_OK, rdd_open_safe_writer(&writer, "newfile", RDD_NO_OVERWRITE));
	CHECK_NOT_NULL_GOTO(writer);
	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, deleteFiles(FILE_LIST, NUM_FILES));
	return 1;

error:
	IGNORE_RESULT(deleteFiles(FILE_LIST, NUM_FILES));

	if (writer != 0) {
		free(writer);
	}
	return 0;

}

// TODO: tests with write mode
// TODO: tests with actual safe writer

static int test_compare_address_address_null()
{
	RDD_WRITER * writer;
	int result;
	CHECK_UINT(RDD_OK, rdd_open_safe_writer(&writer, "testoutput", 0));

	CHECK_UINT_GOTO(RDD_OK, rdd_compare_address(writer, 0, &result));
	CHECK_INT_GOTO(1, result);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer)); // to free resources	
	CHECK_INT(0, remove("testoutput"));
	return 1;
error:
	remove("testoutput");
	return 0;
}

static int test_compare_address_result_null()
{
	RDD_WRITER * writer;
	struct addrinfo address;	// contents are irrelevant for this test
	CHECK_UINT(RDD_OK, rdd_open_safe_writer(&writer, "testoutput", 0));

	CHECK_UINT_GOTO(RDD_BADARG, rdd_compare_address(writer, &address, 0));

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer)); // to free resources
	CHECK_INT(0, remove("testoutput"));	
	return 1;
error:
	remove("testoutput");
	return 0;
}

static int test_compare_address_address_not_null()
{
	RDD_WRITER * writer;
	struct addrinfo address;	// contents are irrelevant for this test
	int result;
	CHECK_UINT(RDD_OK, rdd_open_safe_writer(&writer, "testoutput", 0));

	CHECK_UINT_GOTO(RDD_OK, rdd_compare_address(writer, &address, &result));
	CHECK_INT_GOTO(0, result);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer)); // to free resources
	CHECK_INT(0, remove("testoutput"));
	return 1;
error:
	remove("testoutput");
	return 0;
}


static int
call_tests(void)
{
	int result = 1;
	TEST(test_open_safe_writer_writer_null);
	TEST(test_open_safe_writer_path_null);
	TEST(test_open_safe_writer);

	TEST(test_compare_address_address_null);
	TEST(test_compare_address_result_null);
	TEST(test_compare_address_address_not_null);
	return result;
}

TEST_MAIN;
