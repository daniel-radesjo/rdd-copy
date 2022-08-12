/*
 * Copyright (c) 2002 - 2006, Netherlands Forensic Institute
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


/* A unit-test for the sha1 stream filter.
 */

#ifdef HAVE_CONFIG_H
#include"config.h"
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rdd.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "rdd_internals.h"
#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#endif /* HAVE_OPENSSL */
#include "error.h"
#include "rddtest.h"

/*
 * Command-line arguments:
 * 1: file to calculate the SHA-1 hash of
 * 2: SHA-1 of the file to match with the calculated SHA-1
 * 
 * Output to command line:
 * PASSED
 * STRING FAILED
 * FILE FAILED
 * 
 * Error messages go to stderr.
 */

typedef struct _TESTCASE {
	const char *input;
	unsigned    size;
	const char *sha1;
	const char *sha256;
	const char *sha384;
	const char *sha512;
} TESTCASE;

static TESTCASE test_cases[] = {
	{
		"aa", 
		2,
		"e0c9035898dd52fc65c41454cec9c4d2611bfb37",
		"961b6dd3ede3cb8ecbaacbd68de040cd78eb2ed5889130cceb4c49268ea4d506",
		"c1a447ce5671c0dfd7f920ce5e977cc9afd6323854df6573c96bfee8f1871fb35564c3c42d4a968d20f59a19ebd11eea",
		"f6c5600ed1dbdcfdf829081f5417dccbbd2b9288e0b427e65c8cf67e274b69009cd142475e15304f599f429f260a661b5df4de26746459a3cef7f32006e5d1c1"
	},
	{
		"Listen very carefully, I will say this only once!", 
		49,
		"99e149e89b3c39d39371b18468ec6bd1374aeaf0",
		"fe23c7feb5b7aa56785348ac6545d57cd7839650ce5907b999d1e269dcb9f79e",
		"4bf5e3146cdad5227257d00b76e8b81c52768ff1017e59d50998973d7c2ebccfb91ddbc273f37d536d82de5aea010eae",
		"2b7246eaaf27ffaede3e9c87ab995784eb4bf0a2b4f961e790388ca4709d58b43f8bc02b86b3229a97fa03ed1ec2bdc0d9ac8071932c98472f8f0e31eb5ec4da"
	}
};

static void
filter_error(int shaAlg, char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "[tsha%dfilter] ", shaAlg);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static int newShaStreamfilter(RDD_FILTER **filter, int shaAlg) 
{
	switch(shaAlg)
	{
		case 1:
			return rdd_new_sha1_streamfilter(filter);
		case 256:
			return rdd_new_sha256_streamfilter(filter);
		case 384:
			return rdd_new_sha384_streamfilter(filter);
		case 512:
			return rdd_new_sha512_streamfilter(filter);
		default:
			filter_error(0, "unknown hash algorithm when calling newShaStreamFilter()");
	}
	return -1;
}

static int getShaDigestLength(int shaAlg) 
{
	switch(shaAlg) 
	{
		case 1:
			return SHA_DIGEST_LENGTH;
		case 256:
			return SHA256_DIGEST_LENGTH;
		case 384:
			return SHA384_DIGEST_LENGTH;
		case 512:
			return SHA512_DIGEST_LENGTH;
		default:
			filter_error(0, "unknown hash algorithm when calling getShaDigestLength()");
	}
	return -1;
}

static const char * getExpectedSha(TESTCASE *testCase, int shaAlg)
{
	switch(shaAlg)
	{
		case 1:
			return testCase->sha1;
		case 256:
			return testCase->sha256;
		case 384:
			return testCase->sha384;
		case 512:
			return testCase->sha512;
		default:
			filter_error(0, "unknown hash algorithm when calling getExpectedSha()");
	}
	return NULL;
}

/* Calculates the SHA hashes of a predefined string and checks them.
 */
static void
verifyStrings(unsigned i, TESTCASE *testcase, int shaAlg)
{
	RDD_FILTER *sha_filter = 0;
	RDD_FILTERSET fset;
	char *copy = 0;
	int rc;
	unsigned char sha_digest[SHA512_DIGEST_LENGTH];		// use maximum length
	char shaString[2*SHA512_DIGEST_LENGTH+1];		// use maximum length
	int shaDigestLength = getShaDigestLength(shaAlg);

	char filterName[32];
	if (snprintf(filterName, sizeof(filterName), "SHA-%d-filter", shaAlg) >= sizeof(filterName)) {
		filter_error(shaAlg, "filterName string too small");
	}

	printf("testing SHA-%d with string %u......", shaAlg, i);

	if ((copy = malloc(testcase->size + 1)) == 0) {
		filter_error(shaAlg, "out of memory");
	}

	/* Set up filter and filter set
	 */ 

	rc = rdd_fset_init(&fset);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_init() returned %d instead of RDD_OK", rc);
	}

	/* Set up new SHA digest stream filter.
	 */
	rc = newShaStreamfilter(&sha_filter, shaAlg);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_new_sha%d_streamfilter() returned %d "
				" instead of RDD_OK", rc);
	}
	
	/* Install the filter in the filterset.
	 */
	rc = rdd_fset_add(&fset, filterName, sha_filter);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_add() returned %d instead of RDD_OK", rc);
	}
	
	/* Make a copy of the test input so that we can check whether
	 * the input string is modified (it should not be modified).
	 */
	strcpy(copy, testcase->input);

	/* Push the teststring into the filterset.
	 */
	rc = rdd_fset_push(&fset, (unsigned char *) copy, testcase->size);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_push() returned %d instead of RDD_OK", rc);
	}

	/* Close all filters in the filterset; the final SHA digest is
	 * saved.
	 */
	if ((rc = rdd_fset_close(&fset)) != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_close() returned %d instead of RDD_OK", rc);
	}

	/* Get the SHA digest filter.
	 */
	if ((rc = rdd_fset_get(&fset, filterName, &sha_filter)) != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_get() returned %d instead of RDD_OK", rc);
	}
	
	/* Get the SHA-hash from the filter.
	 */
	rc = rdd_filter_get_result(sha_filter, sha_digest, shaDigestLength);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_filter_get_result() returned %d instead of RDD_OK", rc);
	}
	
	/* Convert the binary digest buffer to a human-readable hex string.
	 */
	rc = rdd_buf2hex(sha_digest, shaDigestLength,
			 shaString, sizeof shaString);	
	if (rc != RDD_OK) {
		filter_error(shaAlg, "cannot convert SHA-%d digest", shaAlg);
	}
	
	const char * expectedSha = getExpectedSha(testcase, shaAlg);
	if (strcmp(shaString, expectedSha) != 0) {
		filter_error(shaAlg, "incorrect SHA-%d hash value", shaAlg);	
	}

	/* Check whether the input buffer has been modified.
	 */
	if (strcmp(copy, testcase->input) != 0) {
		filter_error(shaAlg, "someone modified the input buffer");
	}
	
	if (copy != 0) {
		free(copy);
	}

	printf("OK\n");
}
	
static void 
testFilters(int shaAlg)
{
	unsigned char sha_digest[SHA512_DIGEST_LENGTH]; // use maximum length
	RDD_FILTER *f = 0;
	RDD_FILTER *g = 0;
	RDD_FILTERSET fset;
	int rc;
	char filterName[32];
	int shaDigestLength = getShaDigestLength(shaAlg);
	if (snprintf(filterName, sizeof(filterName), "SHA-%d-filter", shaAlg) >= sizeof(filterName)) {
		filter_error(shaAlg, "filterName string too small");
	}
	char filterName2[32];
	if (snprintf(filterName, sizeof(filterName), "SHA-%d-filter 2", shaAlg) >= sizeof(filterName)) {
		filter_error(shaAlg, "filterName string too small");
	}

	printf("Testing SHA-%d functions on bad behaviour.\n", shaAlg);

	rc = rdd_fset_init(&fset);

	rc = rdd_fset_get(&fset, "xx", &f);
	if (rc != RDD_NOTFOUND) {
		filter_error(shaAlg, "rdd_fset_get() should return RDD_NOTFOUND when there are no filters in the filterset");
	}
 
	rc = newShaStreamfilter(&f, shaAlg);

	rc = rdd_fset_add(&fset, "", f);
	if (rc != RDD_BADARG) {
		filter_error(shaAlg, "rdd_fset_add() returned %d instead of RDD_BAD_ARG", rc);
	}
	
	/*forget everything, start with a new filterset*/
	rc = rdd_fset_clear(&fset);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_clear() returned %d instead of RDD_OK", rc);
	}
	
	rc = rdd_fset_init(&fset);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_init() returned %d instead of RDD_OK", rc);
	}
	
	/*build a couple of filters and add them to the filter set*/
	rc = rdd_new_sha1_streamfilter(&f);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_sha1_stream_filter() returned %d, should return RDD_OK", rc);
	}
	
	rc = rdd_new_sha1_streamfilter(&g);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_sha1_stream_filter() returned %d, should return RDD_OK", rc);
	}
	
	rc = rdd_fset_add(&fset, filterName, f);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_add() returned %d instead of RDD_OK", rc);
	}
	
	rc = rdd_fset_add(&fset, filterName, g);
	if (rc != RDD_EEXISTS) {
		filter_error(shaAlg, "rdd_fset_add() accepted an existing filter name");
	}

	rc = rdd_fset_add(&fset, filterName2, g);

	f = g = 0;

	rc = rdd_fset_get(&fset, "xx", &f);
	if (rc != RDD_NOTFOUND) {
		filter_error(shaAlg, "rdd_fset_get() found non-existing filter.");
	}

	/* Get buffers from filters.
	 */
	rc = rdd_fset_push(&fset, (unsigned char *) "olla vogala", 12);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_push() returned %d instead of RDD_OK", rc); 
	}

	rc = rdd_fset_close(&fset);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_close() returned %d instead of RDD_OK", rc); 
	}

	rc = rdd_fset_get(&fset, filterName, &f);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_fset_get() returned %d instead of RDD_OK", rc); 
	}

	
	rc = rdd_filter_get_result(f, sha_digest, shaDigestLength);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_filter_get_result() failed to get SHA-%d result", shaAlg); 
	}

	rc = rdd_filter_get_result(f, sha_digest, 0);
	if (rc != RDD_ESPACE) {
		filter_error(shaAlg, "undersized (0) SHA-%d buffer was not detected", shaAlg);
	}

	rc = rdd_filter_get_result(f, sha_digest, 19);
	if (rc != RDD_ESPACE) {
		filter_error(shaAlg, "undersized (19) SHA-%d buffer was not detected", shaAlg);
	}

	rc = rdd_filter_get_result(f, sha_digest, 100);
	if (rc != RDD_OK) {
		filter_error(shaAlg, "rdd_filter_get_result() failed to get SHA-%d result", shaAlg); 
	}
}

int
main(int argc, char **argv)
{
	unsigned i;

	printf("------------------Testing SHA routines\n");

	for (i = 0; i < (sizeof test_cases) / sizeof(test_cases[0]); i++) {
		verifyStrings(i+1, &test_cases[i], 1); 		// SHA-1
		verifyStrings(i+1, &test_cases[i], 256); 	// SHA-256
		verifyStrings(i+1, &test_cases[i], 384); 	// SHA-384
		verifyStrings(i+1, &test_cases[i], 512); 	// SHA-512
	}

	testFilters(1);		// SHA-1
	testFilters(256);	// SHA-256
	testFilters(384);	// SHA-384
	testFilters(512); 	// SHA-512

	printf("------------------Finished testing SHA routines\n");
	
	return 0;
}
