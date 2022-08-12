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
#include "strerror.c"

#include "testhelper.h"

static int test_copymsg_bufsize_0()
{
	CHECK_UINT(RDD_NOMEM, copymsg(0, 0, "message"));
	return 1;
}

static int test_copymsg_msg_0()
{
	char buffer[10];
	CHECK_UINT(RDD_BADARG, copymsg(buffer, sizeof(buffer), 0));
	return 1;
}

static int test_copymsg_too_small_buffer()
{
	char buffer[10];
	CHECK_UINT(RDD_NOMEM, copymsg(buffer, sizeof(buffer), "01234567890"));
	return 1;
}

static int test_copymsg()
{
	char buffer[10];
	CHECK_UINT(RDD_OK, copymsg(buffer, sizeof(buffer), "message!"));
	CHECK_STRING("message!", buffer);
	return 1;
}

static int test_get_message_negative() {
	CHECK_UINT(0, (int) get_message(-1));
	return 1;
}

static int test_get_message_too_large() {
	CHECK_UINT(0, (int) get_message(500));
	return 1;
}

static int test_get_message() {
	CHECK_STRING("out of memory", get_message(RDD_NOMEM));
	return 1;
}

static int test_rdd_strerror_buf_0() {
	CHECK_UINT(RDD_BADARG, rdd_strerror(RDD_OK, 0, 0));
	return 1;
}

static int test_rdd_strerror_rc_negative() {
	char buffer[20];
	CHECK_UINT(RDD_BADARG, rdd_strerror(-1, buffer, sizeof(buffer)));
	return 1;
}

static int test_rdd_strerror_rc_too_large() {
	char buffer[20];
	CHECK_UINT(RDD_BADARG, rdd_strerror(500, buffer, sizeof(buffer)));
	return 1;
}

static int test_rdd_strerror_buffer_too_small() {
	char buffer[5];
	CHECK_UINT(RDD_NOMEM, rdd_strerror(RDD_EREAD, buffer, sizeof(buffer)));
	return 1;
}

static int test_rdd_strerror() {
	char buffer[20];
	CHECK_UINT(RDD_OK, rdd_strerror(RDD_ERANGE, buffer, sizeof(buffer)));
	CHECK_STRING("number out of range", buffer);
	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_copymsg_bufsize_0);
	TEST(test_copymsg_msg_0);
	TEST(test_copymsg_too_small_buffer);
	TEST(test_copymsg);

	TEST(test_get_message_negative);
	TEST(test_get_message_too_large);
	TEST(test_get_message);

	TEST(test_rdd_strerror_buf_0);
	TEST(test_rdd_strerror_rc_negative);
	TEST(test_rdd_strerror_rc_too_large);
	TEST(test_rdd_strerror_buffer_too_small);
	TEST(test_rdd_strerror);

	return result;
}

TEST_MAIN;
