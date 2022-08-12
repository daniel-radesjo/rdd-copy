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
#include <string.h>

#include "mockcopier.h"
#include "mockreader.h"

#include "testhelper.h"

static RDD_COPIER *mockcopier;
static RDD_READER *mockreader;

static RDD_FILTERSET *filterset;

static RDD_COPIER_RETURN *rdd_copier_return;

static int
setup()
{
	CHECK_UINT(RDD_OK,mockcopier_open(&mockcopier));

	CHECK_UINT(RDD_OK,mockreader_open(&mockreader));

	CHECK_TRUE((filterset = calloc(1, sizeof(filterset))) != 0);

	CHECK_UINT(RDD_OK, rdd_fset_init(filterset));

	CHECK_TRUE((rdd_copier_return = calloc(1, sizeof(rdd_copier_return))) != 0);

	return 1;
}

static int
teardown()
{
	CHECK_UINT(RDD_OK,rdd_copy_free(mockcopier));
	CHECK_UINT(RDD_OK,rdd_reader_close(mockreader, 0));

	CHECK_UINT(RDD_OK, rdd_fset_clear(filterset));

	free(rdd_copier_return);

	return 1;
}

static int
test_new_copier_self_null()
{

	CHECK_UINT(RDD_BADARG, rdd_new_copier(0, mockcopier->ops, sizeof(mockcopier->state)) );

	return 1;
}

static int
test_new_copier_ops_null()
{
	RDD_COPIER *copier;
	CHECK_UINT(RDD_BADARG, rdd_new_copier(&copier, 0, sizeof(mockcopier->state)))

	return 1;
}

static int
test_copy_exec()
{

	mockcopier_stub_copy_exec(mockcopier, RDD_OK);

	CHECK_UINT(RDD_OK, rdd_copy_exec(mockcopier, mockreader,filterset,rdd_copier_return ));

	CHECK_TRUE(mockcopier_verify_copy_exec(mockcopier, 1, mockreader, filterset, rdd_copier_return));

	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	SAFE_TEST(test_new_copier_self_null);
	SAFE_TEST(test_new_copier_ops_null);
	SAFE_TEST(test_copy_exec);

	return result;
}

TEST_MAIN
;
