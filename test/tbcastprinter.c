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

#define COUNT_MOCKPRINTERS 2

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "rdd.h"

#include "testhelper.h"
#include "msgprinter.h"
#include "mockprinter.h"

static RDD_MSGPRINTER *bcastprinter;
static RDD_MSGPRINTER *mockprinters[COUNT_MOCKPRINTERS];

static int
setup()
{
	unsigned i;

	for (i = 0; i < COUNT_MOCKPRINTERS; i++)
	{
		CHECK_UINT(RDD_OK, mockprinter_open(&mockprinters[i]));
	}

	CHECK_UINT(RDD_OK, rdd_mp_open_bcastprinter(&bcastprinter, COUNT_MOCKPRINTERS, mockprinters));

	return 1;
}

static int
teardown()
{
	memset(mockprinters, 0, sizeof(mockprinters));
	if (bcastprinter != NULL)
	{
		rdd_mp_close(bcastprinter, RDD_MP_RECURSE);
		bcastprinter = NULL;
	}
	return 1;
}

static int
test_bcastprinter_open_null_printers()
{
	RDD_MSGPRINTER *bcastprinter;

	CHECK_UINT(RDD_BADARG, rdd_mp_open_bcastprinter(&bcastprinter, 1, NULL));

	return 1;
}

static int
test_bcastprinter_print()
{

	rdd_message_t mesg_type = RDD_MSG_INFO;
	int errorcode = 0;
	const char *mesg = "message";
	int i;

	rdd_mp_print(bcastprinter, mesg_type, errorcode, mesg);

	for (i = 0; i < COUNT_MOCKPRINTERS; i++)
	{
		CHECK_TRUE(mockprinter_verify_print(mockprinters[i], 1, mesg_type, errorcode, mesg));
	}
	return 1;
}

static int
test_bcastprinter_close_success_with_recurse()
{
	int recurse = 1;
	int i;

	for (i = 0; i < COUNT_MOCKPRINTERS; i++)
	{
		mockprinter_stub_close(mockprinters[i], RDD_OK);
	}

	CHECK_UINT(RDD_OK, rdd_mp_close(bcastprinter, recurse));

	for (i = 0; i < COUNT_MOCKPRINTERS; i++)
	{
		CHECK_TRUE(mockprinter_verify_close(mockprinters[i], 1, recurse));
	}

	return 1;
}

static int
test_bcastprinter_close_success_no_recurse()
{
	int recurse = 0;
	int i;

	CHECK_UINT(RDD_OK, rdd_mp_close(bcastprinter, recurse));

	for (i = 0; i < COUNT_MOCKPRINTERS; i++)
	{
		CHECK_TRUE(mockprinter_verify_close(mockprinters[i], 0, recurse));
	}

	return 1;
}

static int
test_bcastprinter_close_fail_with_recurse()
{
	int recurse = 1;
	int i;

	for (i = 0; i < COUNT_MOCKPRINTERS; i++)
	{
		mockprinter_stub_close(mockprinters[i], RDD_ECLOSE);
	}

	CHECK_UINT(RDD_ECLOSE, rdd_mp_close(bcastprinter, recurse));

	// only first mockprinter is called
	CHECK_TRUE(mockprinter_verify_close(mockprinters[0], 1, recurse));

	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_bcastprinter_open_null_printers);
	SAFE_TEST(test_bcastprinter_print);
	SAFE_TEST(test_bcastprinter_close_success_with_recurse);
	SAFE_TEST(test_bcastprinter_close_success_no_recurse);
	SAFE_TEST(test_bcastprinter_close_fail_with_recurse);

	return result;
}

TEST_MAIN
;
