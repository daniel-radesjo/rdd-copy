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
#include "hashcontainer.h"

#include "testhelper.h"

static uint8_t hashValue[RDD_MAX_DIGEST_LENGTH]; 

static int test_rdd_new_hashcontainer_null()
{
	CHECK_UINT(RDD_BADARG, rdd_new_hashcontainer(0));
	return 1;
}

static int test_rdd_new_hashcontainer()
{
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);	
	free(container);
	return 1;;
}

static int test_rdd_set_hash_hashcontainer_null()
{
	CHECK_UINT(RDD_BADARG, rdd_set_hash(0, RDD_MD5, hashValue));
	return 1;
}

static int test_rdd_set_hash_hashtype_null()
{
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_set_hash(container, 0, hashValue));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_set_hash_hashtype_unknown()
{
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_set_hash(container, "unknown", hashValue));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_set_hash_hash_null()
{
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_set_hash(container, RDD_MD5, 0));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_get_hash_hashcontainer_null()
{
	uint8_t hash[MD5_DIGEST_LENGTH];
	CHECK_UINT(RDD_BADARG, rdd_get_hash(0, RDD_MD5, hash));
	return 1;
}

static int test_rdd_get_hash_hashtype_null()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[RDD_MAX_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_get_hash(container, 0, hash));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_get_hash_hashtype_unknown()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[RDD_MAX_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_get_hash(container, "unknown", hash));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_get_hash_hash_null()
{
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_get_hash(container, RDD_MD5, 0));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_get_hash_md5_not_present()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[MD5_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_NOTFOUND, rdd_get_hash(container, RDD_MD5, hash));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_get_hash_sha1_not_present()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[SHA_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_NOTFOUND, rdd_get_hash(container, RDD_SHA1, hash));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_get_hash_sha256_not_present()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[SHA256_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_NOTFOUND, rdd_get_hash(container, RDD_SHA256, hash));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_get_hash_sha384_not_present()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[SHA384_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_NOTFOUND, rdd_get_hash(container, RDD_SHA384, hash));
	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_get_hash_sha512_not_present()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[SHA512_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_NOTFOUND, rdd_get_hash(container, RDD_SHA512, hash));
	free(container);
	return 1;

error:
	free(container);
	return 0;	;
}

static int test_rdd_hash_present_hashcontainer_null()
{
	int present;
	CHECK_UINT(RDD_BADARG, rdd_hash_present(0, RDD_MD5, &present));
	return 1;
}

static int test_rdd_hash_present_hashtype_null()
{
	int present;
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_hash_present(container, 0, &present));

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_hash_present_present_null()
{
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_hash_present(container, RDD_MD5, 0));

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_hash_present_hashtype_unknown()
{
	int present;
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_hash_present(container, "unknown", &present));

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_hash_present_nothing_present()
{
	int present;
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_MD5, &present));
	CHECK_UINT_GOTO(0, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA1, &present));
	CHECK_UINT_GOTO(0, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA256, &present));
	CHECK_UINT_GOTO(0, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA384, &present));
	CHECK_UINT_GOTO(0, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA512, &present));
	CHECK_UINT_GOTO(0, present);

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_hash_present_one_present()
{
	int present;
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_MD5, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_MD5, &present));
	CHECK_UINT_GOTO(1, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA1, &present));
	CHECK_UINT_GOTO(0, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA256, &present));
	CHECK_UINT_GOTO(0, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA384, &present));
	CHECK_UINT_GOTO(0, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA512, &present));
	CHECK_UINT_GOTO(0, present);

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_hash_present_multiple_present()
{
	int present;
	RDD_HASH_CONTAINER * container = 0;

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);


	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_MD5, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_SHA256, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_SHA384, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_MD5, &present));
	CHECK_UINT_GOTO(1, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA1, &present));
	CHECK_UINT_GOTO(0, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA256, &present));
	CHECK_UINT_GOTO(1, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA384, &present));
	CHECK_UINT_GOTO(1, present);

	CHECK_UINT_GOTO(RDD_OK, rdd_hash_present(container, RDD_SHA512, &present));
	CHECK_UINT_GOTO(0, present);

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_set_get_hash_md5()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[MD5_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_MD5, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_get_hash(container, RDD_MD5, hash));

	CHECK_UCHAR_ARRAY_GOTO(hash, hashValue, MD5_DIGEST_LENGTH);

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_set_get_hash_sha1()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[SHA_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_SHA1, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_get_hash(container, RDD_SHA1, hash));

	CHECK_UCHAR_ARRAY_GOTO(hash, hashValue, SHA_DIGEST_LENGTH);

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_set_get_hash_sha256()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[SHA256_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_SHA256, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_get_hash(container, RDD_SHA256, hash));

	CHECK_UCHAR_ARRAY_GOTO(hash, hashValue, SHA256_DIGEST_LENGTH);

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_set_get_hash_sha384()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[SHA384_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_SHA384, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_get_hash(container, RDD_SHA384, hash));

	CHECK_UCHAR_ARRAY_GOTO(hash, hashValue, SHA384_DIGEST_LENGTH);

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_set_get_hash_sha512()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[SHA512_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_SHA512, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_get_hash(container, RDD_SHA512, hash));

	CHECK_UCHAR_ARRAY_GOTO(hash, hashValue, SHA512_DIGEST_LENGTH);

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int test_rdd_set_get_hash_multiple()
{
	RDD_HASH_CONTAINER * container = 0;
	uint8_t hash[RDD_MAX_DIGEST_LENGTH];

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&container));
	CHECK_NOT_NULL(container);

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_MD5, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(container, RDD_SHA1, hashValue));

	CHECK_UINT_GOTO(RDD_OK, rdd_get_hash(container, RDD_MD5, hash));

	CHECK_UCHAR_ARRAY_GOTO(hash, hashValue, MD5_DIGEST_LENGTH);

	CHECK_UINT_GOTO(RDD_OK, rdd_get_hash(container, RDD_SHA1, hash));

	CHECK_UCHAR_ARRAY(hash, hashValue, SHA_DIGEST_LENGTH);

	free(container);
	return 1;

error:
	free(container);
	return 0;	
}

static int
call_tests(void)
{
	/* 
	 * Initialize the hash value (used for all hash types).
	 */
	int i;
	for (i=0; i<RDD_MAX_DIGEST_LENGTH; i++) {
		hashValue[i] = i%256;
	}
	int result = 1;

	TEST(test_rdd_new_hashcontainer_null);
	TEST(test_rdd_new_hashcontainer);

	TEST(test_rdd_set_hash_hashcontainer_null);
	TEST(test_rdd_set_hash_hashtype_null);
	TEST(test_rdd_set_hash_hashtype_unknown);
	TEST(test_rdd_set_hash_hash_null);

	TEST(test_rdd_get_hash_hashcontainer_null);
	TEST(test_rdd_get_hash_hashtype_null);
	TEST(test_rdd_get_hash_hashtype_unknown);
	TEST(test_rdd_get_hash_hash_null);
	
	TEST(test_rdd_get_hash_md5_not_present);
	TEST(test_rdd_get_hash_sha1_not_present);
	TEST(test_rdd_get_hash_sha256_not_present);
	TEST(test_rdd_get_hash_sha384_not_present);
	TEST(test_rdd_get_hash_sha512_not_present);

	TEST(test_rdd_hash_present_hashcontainer_null);
	TEST(test_rdd_hash_present_hashtype_null);
	TEST(test_rdd_hash_present_present_null);
	TEST(test_rdd_hash_present_hashtype_unknown);
	TEST(test_rdd_hash_present_nothing_present);
	TEST(test_rdd_hash_present_one_present);
	TEST(test_rdd_hash_present_multiple_present);

	TEST(test_rdd_set_get_hash_md5);
	TEST(test_rdd_set_get_hash_sha1);
	TEST(test_rdd_set_get_hash_sha256);
	TEST(test_rdd_set_get_hash_sha384);
	TEST(test_rdd_set_get_hash_sha512);
	TEST(test_rdd_set_get_hash_multiple);

	return result;
}

TEST_MAIN;
