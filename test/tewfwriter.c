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
#include "ewfwriter.c"

#include "testhelper.h"

static int 
test_path_exists_path_null()
{
	struct stat info;
	CHECK_UINT(1, path_exists(0, &info));
	return 1;
} 

static int 
test_path_exists_exists_info_null()
{
	CHECK_UINT(1, path_exists("existing_file.E01", 0));
	return 1;
} 

static int 
test_path_exists_notexists_info_null()
{
	CHECK_UINT(0, path_exists("nonexistingfile.txt", 0));
	return 1;
}

static int 
test_path_exists_true()
{
	struct stat info;
	CHECK_UINT(1, path_exists("existing_file.E01", &info));
	return 1;
} 

static int 
test_path_exists_false()
{
	struct stat info;
	CHECK_UINT(0, path_exists("nonexistingfile.txt", &info));
	return 1;
}

static int 
test_rdd_open_ewf_writer_writer_null()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_open_ewf_writer(0, "newfile", 0, 1, 0, hashcontainer));

	free(hashcontainer);
	return 1;

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	return 0;
}

static int 
test_rdd_open_ewf_writer_path_null_no_overwrite()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_open_ewf_writer(&writer, 0, 0, 1, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NULL_GOTO(writer);

	free(hashcontainer);
	return 1;

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	return 0;
}

static int 
test_rdd_open_ewf_writer_path_null_overwrite()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_open_ewf_writer(&writer, 0, 0, 1, RDD_OVERWRITE, hashcontainer));
	CHECK_NULL_GOTO(writer);
	free(hashcontainer);
	return 1;

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	return 0;
}

static int 
test_rdd_open_ewf_writer_path_null_overwrite_ask()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_open_ewf_writer(&writer, 0, 0, 1, RDD_OVERWRITE_ASK, hashcontainer));
	CHECK_NULL_GOTO(writer);

	free(hashcontainer);
	return 1;

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	return 0;
}

static int 
test_rdd_open_ewf_writer_hashcontainer_null()
{
	RDD_WRITER * writer = 0;

	CHECK_UINT(RDD_BADARG, rdd_open_ewf_writer(&writer, 0, 0, 1, RDD_NO_OVERWRITE, 0));
	CHECK_NULL(writer);

	return 1;

}

static int
test_rdd_open_ewf_writer_compress_option_invalid_0()
{
	RDD_WRITER *writer = 0;

	CHECK_UINT(RDD_BADARG, rdd_open_ewf_writer(&writer, 0, 0, 0, RDD_NO_OVERWRITE, 0));
	CHECK_NULL(writer);

	return 1;
}

static int
test_rdd_open_ewf_writer_compress_option_invalid_5()
{
	RDD_WRITER *writer = 0;

	CHECK_UINT(RDD_BADARG, rdd_open_ewf_writer(&writer, 0, 0, 5, RDD_NO_OVERWRITE, 0));
	CHECK_NULL(writer);

	return 1;
}



static int 
test_rdd_open_ewf_writer()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "newfile", 0, 1, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);
	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);

	remove("newfile.E01");

	return 1;
error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	remove("newfile.E01");
	return 0;

}

static int 
test_rdd_open_ewf_writer_splitlen()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "newfile", RDD_EWF_MIN_SPLITLEN, 1, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);
	remove("newfile.E01");
	return 1;

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	remove("newfile.E01");
	return 0;
}

static int 
test_rdd_open_ewf_writer_splitlen_toosmall()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_BADARG, rdd_open_ewf_writer(&writer, "newfile", 100, 1, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NULL_GOTO(writer);

	free(hashcontainer);
	return 1;

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	return 0;
}

static int 
test_rdd_open_ewf_writer_existing_no_overwrite()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_EEXISTS, rdd_open_ewf_writer(&writer, "existing_file", 0, 1, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NULL_GOTO(writer);	

	free(hashcontainer);
	return 1;
error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	return 0;
}

static int 
test_rdd_open_ewf_writer_existing_overwrite()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "existing_file", 0, 1, RDD_OVERWRITE, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);
	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);

	return 1;
error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	return 0;
}

static int 
test_rdd_open_ewf_writer_existing_overwrite_ask()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "existing_file", 0, 1, RDD_OVERWRITE_ASK, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);

	return 1;

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	return 0;
}

static int 
test_ewf_write_zero_bytes()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	unsigned char buf[] = "012345";
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "newfile", 0, 1, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_write(writer, buf, 0));

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);
	remove("newfile.E01");
	return 1;	

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	remove("newfile.E01");
	return 0;
}

static int 
check_ewf_file(char * filenames[], int numfiles, void * contents, size_t size, rdd_count_t segment_size, uint8_t * md5_hash, uint8_t * sha1_hash, int compress_level)
{
	uint8_t flags = libewf_get_access_flags_read();
	libewf_handle_t * handle = 0;
	int8_t compression_level;
	uint8_t compression_flags;
	size64_t retrieved_segment_size;
	const unsigned int BUFFER_LENGTH = 1024;
	uint8_t retrieved_md5_hash[MD5_DIGEST_LENGTH];
	uint8_t retrieved_sha1_hash[SHA_DIGEST_LENGTH];
	unsigned char retrieved_buffer[BUFFER_LENGTH];
	uint8_t media_type;
	uint8_t media_flags;
	uint8_t format;
	ssize_t num_bytes;
	ssize_t total_bytes_read;
	ssize_t remaining_bytes;
	ssize_t offset;
	ssize_t chunk_size;

	libewf_error_t *err = 0;
	
	if (libewf_handle_initialize(&handle, &err) == -1) {
		libewf_error_free(&err);
		printf("can't init ewf handle\n");
		goto error;
	}

	if (handle == 0) {
		libewf_error_free(&err);
		printf("can't init ewf handle\n");
		goto error;
	}

	if (libewf_handle_open(handle, filenames, numfiles, flags, &err) == -1) {
		libewf_error_free(&err);
		printf("can't open ewf handle\n");
		goto error;
	}

	/* Check media type */
	if (libewf_handle_get_media_type(handle, &media_type, &err) == -1) {
		libewf_error_free(&err);
		printf("can't get ewf media type\n");
		goto error;
	}	
	CHECK_UINT_GOTO(LIBEWF_MEDIA_TYPE_FIXED, media_type);

	/* Check media flags */
	if (libewf_handle_get_media_flags(handle, &media_flags, &err) == -1) {
		libewf_error_free(&err);
		printf("can't get ewf media flags\n");
		goto error;
	}	
	CHECK_UINT_GOTO(LIBEWF_MEDIA_FLAG_PHYSICAL, media_flags & LIBEWF_MEDIA_FLAG_PHYSICAL);

	/* Check format */
	if (libewf_handle_get_format(handle, &format, &err) == -1) {
		libewf_error_free(&err);
		printf("can't get ewf format\n");
		goto error;
	}	
	CHECK_UINT_GOTO(LIBEWF_FORMAT_ENCASE6, format);

	/* Check compression */
	if (libewf_handle_get_compression_values(handle, &compression_level, &compression_flags, &err) == -1) {
		libewf_error_free(&err);
		printf("can't get ewf compression values\n");
		goto error;
	}	

	// correct compress_level with -1 to compensate parameter-voodoo in ewfwriter.c
	CHECK_UINT_GOTO((compress_level -1), compression_level);
	//CHECK_UINT_GOTO(0, compression_flags);


	/* Check segment file size */
	if (libewf_handle_get_maximum_segment_size(handle, &retrieved_segment_size, &err) == -1) {
		libewf_error_free(&err);
		printf("can't get ewf segment file size\n");
		goto error;
	}	

	if (segment_size == 0) {
		// No segment size set, should be the default value.
		CHECK_UINT64_GOTO((size64_t) LIBEWF_DEFAULT_SEGMENT_FILE_SIZE, retrieved_segment_size);

	} //else {
		// Somehow this doesn't match exactly
	//	if (retrieved_segment_size != segment_size) {
	//		goto error;
	//	}
	//}

	/* Check md5 hash */
	if (md5_hash != 0) {
		if (libewf_handle_get_md5_hash(handle, retrieved_md5_hash, sizeof(retrieved_md5_hash), &err) == -1) {
			libewf_error_free(&err);
			printf("can't get ewf md5 hash");
			goto error;
		}
	
		CHECK_UCHAR_ARRAY_GOTO(md5_hash, retrieved_md5_hash, MD5_DIGEST_LENGTH); 
	}

	if (sha1_hash != 0) {
		/* Check sha1 hash */
	
		if (libewf_handle_get_sha1_hash(handle, retrieved_sha1_hash, sizeof(retrieved_sha1_hash), &err) == -1) {
			libewf_error_free(&err);
			printf("can't get ewf sha1 hash\n");
			goto error;
		}
	
		CHECK_UCHAR_ARRAY_GOTO(sha1_hash, retrieved_sha1_hash, SHA_DIGEST_LENGTH);

	}


	total_bytes_read = 0;
	offset = 0;
	while (total_bytes_read < size) {

		if ((num_bytes = libewf_handle_read_buffer(handle, retrieved_buffer, BUFFER_LENGTH, &err)) == -1) {
			libewf_error_free(&err);
			printf("can't read ewf buffer\n");
			goto error;
		}
		total_bytes_read += num_bytes;
		remaining_bytes = size - total_bytes_read;
		if (remaining_bytes < BUFFER_LENGTH) {
			chunk_size = remaining_bytes;
		} else {
			chunk_size = BUFFER_LENGTH;
		}

		CHECK_UCHAR_ARRAY_GOTO(((unsigned char *)(contents + offset)), retrieved_buffer, chunk_size);
		offset = total_bytes_read;
	}


	CHECK_UINT_GOTO(size, total_bytes_read);

	if (libewf_handle_close(handle, &err) == -1) {
		libewf_error_free(&err);
		printf("can't close ewf handle\n");
		goto error;
	}

	if (libewf_handle_free(&handle, &err) == -1) {
		libewf_error_free(&err);
		printf("can't free ewf handle\n");
		goto error;
	}

	return 1;

error:
	if (handle != 0) {
		libewf_handle_close(handle, &err);
		libewf_handle_free(&handle, &err);
	}

	return 0;	

}

static int 
test_ewf_write_compression_best()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	unsigned char buf[] = "012345";
	int compress_level = 3;
	uint8_t md5_hash[MD5_DIGEST_LENGTH];
	uint8_t sha1_hash[SHA_DIGEST_LENGTH];
	int i;
	for (i=0; i<MD5_DIGEST_LENGTH; i++) {
		md5_hash[i] = i*6;
	}
	for (i=0; i<SHA_DIGEST_LENGTH; i++) {
		sha1_hash[i] = i*7;
	}

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);
	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(hashcontainer, RDD_MD5, md5_hash));
	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(hashcontainer, RDD_SHA1, sha1_hash));

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "newfile", 0, compress_level, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_write(writer, buf, sizeof(buf)));

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);

	char * filenames[1];
	filenames[0] = "newfile.E01";

	int result = check_ewf_file(filenames, 1, buf, sizeof(buf), 0, md5_hash, sha1_hash, compress_level);
	remove("newfile.E01");
	return result;	

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	remove("newfile.E01");
	return 0;
}

static int 
test_ewf_write_compression_fast()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	unsigned char buf[] = "012345";
	int compress_level = 2;
	uint8_t md5_hash[MD5_DIGEST_LENGTH];
	uint8_t sha1_hash[SHA_DIGEST_LENGTH];
	int i;
	for (i=0; i<MD5_DIGEST_LENGTH; i++) {
		md5_hash[i] = i*6;
	}
	for (i=0; i<SHA_DIGEST_LENGTH; i++) {
		sha1_hash[i] = i*7;
	}

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);
	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(hashcontainer, RDD_MD5, md5_hash));
	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(hashcontainer, RDD_SHA1, sha1_hash));

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "newfile", 0, compress_level, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_write(writer, buf, sizeof(buf)));

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);

	char * filenames[1];
	filenames[0] = "newfile.E01";

	int result = check_ewf_file(filenames, 1, buf, sizeof(buf), 0, md5_hash, sha1_hash, compress_level);
	remove("newfile.E01");
	return result;

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	remove("newfile.E01");
	return 0;
}

static int
test_ewf_write_compression_none()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	unsigned char buf[] = "012345";
	int compress_level = 1;
	uint8_t md5_hash[MD5_DIGEST_LENGTH];
	uint8_t sha1_hash[SHA_DIGEST_LENGTH];
	int i;
	for (i=0; i<MD5_DIGEST_LENGTH; i++) {
		md5_hash[i] = i*6;
	}
	for (i=0; i<SHA_DIGEST_LENGTH; i++) {
		sha1_hash[i] = i*7;
	}

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);
	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(hashcontainer, RDD_MD5, md5_hash));
	CHECK_UINT_GOTO(RDD_OK, rdd_set_hash(hashcontainer, RDD_SHA1, sha1_hash));

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "newfile", 0, compress_level, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_write(writer, buf, sizeof(buf)));

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);

	char * filenames[1];
	filenames[0] = "newfile.E01";

	int result = check_ewf_file(filenames, 1, buf, sizeof(buf), 0, md5_hash, sha1_hash, compress_level);
	remove("newfile.E01");
	return result;

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	remove("newfile.E01");
	return 0;
}

static int
test_ewf_write_multiple()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	unsigned char buf[] = "012345abcdefgh***";
	int compress_level = 3;
	uint8_t md5_hash[MD5_DIGEST_LENGTH];
	uint8_t sha1_hash[SHA_DIGEST_LENGTH];
	int i;
	for (i=0; i<MD5_DIGEST_LENGTH; i++) {
		md5_hash[i] = i*6;
	}
	for (i=0; i<SHA_DIGEST_LENGTH; i++) {
		sha1_hash[i] = i*7;
	}

	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL(hashcontainer);
	if (rdd_set_hash(hashcontainer, RDD_MD5, md5_hash) != RDD_OK) {
		goto error;
	}
	if (rdd_set_hash(hashcontainer, RDD_SHA1, sha1_hash) != RDD_OK) {
		goto error;
	}

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "newfile", 0, compress_level, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_write(writer, buf, 6));

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_write(writer, buf+6, 8));

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_write(writer, buf+14, 4)); // also write the null terminator.

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);

	char * filenames[1];
	filenames[0] = "newfile.E01";

	int result = check_ewf_file(filenames, 1, buf, sizeof(buf), 0, md5_hash, sha1_hash, compress_level);
	remove("newfile.E01");
	return result;	

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	remove("newfile.E01");
	return 0;
}

static int 
test_ewf_write_segments()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	int i, j;
	unsigned char * buf = 0;
	unsigned int offset;
	int compress_level = 3;

	if ((buf = malloc(2*1024*1024)) == 0) {
		goto error;
	}
	
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	CHECK_NOT_NULL_GOTO(hashcontainer);

	/* segment size is 1 MiB (the minimum) */
	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "newfile", RDD_EWF_MIN_SPLITLEN, compress_level, RDD_NO_OVERWRITE, hashcontainer));
	CHECK_NOT_NULL_GOTO(writer);

	offset = 0;
	for (i=0; i<2*1024; i++) {
		for (j=0; j<1024; j++) {
			buf[offset+j] = random()%256; // we need random data to prevent compression
		}
		CHECK_UINT_GOTO(RDD_OK, rdd_writer_write(writer, buf + offset, 1024));

		offset += 1024;
	}

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer));

	free(hashcontainer);


	char * filenames[3];
	filenames[0] = "newfile.E01";
	filenames[1] = "newfile.E02";
	filenames[2] = "newfile.E03";	

	int result = check_ewf_file(filenames, 3, buf, 2 * 1024 * 1024, RDD_EWF_MIN_SPLITLEN, 0, 0, compress_level);
	remove("newfile.E01");
	remove("newfile.E02");
	remove("newfile.E03");
	free(buf);

	return result;	

error:
	if (hashcontainer != 0) {
		free(hashcontainer);
	}
	if (writer != 0) {
		free(writer);
	}
	if (buf != 0) {
		free(buf);
	}

	remove("newfile.E01");
	remove("newfile.E02");
	remove("newfile.E03");
	return 0;
}

static int test_compare_address_address_null()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	int result;
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	if (hashcontainer == 0){
		goto error;
	}

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "testoutput", 0, 1, RDD_NO_OVERWRITE, hashcontainer));

	CHECK_UINT_GOTO(RDD_OK, rdd_compare_address(writer, 0, &result));
	CHECK_INT_GOTO(1, result);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer)); // to free resources	
	remove("testoutput.E01");
	return 1;
error:
	remove("testoutput.E01");
	return 0;
}

static int test_compare_address_result_null()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	struct addrinfo address;	// contents are irrelevant for this test
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	if (hashcontainer == 0){
		goto error;
	}

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "testoutput", 0, 1, RDD_NO_OVERWRITE, hashcontainer));

	CHECK_UINT_GOTO(RDD_BADARG, rdd_compare_address(writer, &address, 0));

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer)); // to free resources
	remove("testoutput.E01");
	return 1;
error:
	remove("testoutput.E01");
	return 0;
}

static int test_compare_address_address_not_null()
{
	RDD_HASH_CONTAINER * hashcontainer = 0;
	RDD_WRITER * writer = 0;
	int result;
	struct addrinfo address;	// contents are irrelevant for this test
	CHECK_UINT(RDD_OK, rdd_new_hashcontainer(&hashcontainer));
	if (hashcontainer == 0){
		goto error;
	}

	CHECK_UINT_GOTO(RDD_OK, rdd_open_ewf_writer(&writer, "testoutput", 0, 1, RDD_NO_OVERWRITE, hashcontainer));

	CHECK_UINT_GOTO(RDD_OK, rdd_compare_address(writer, &address, &result));
	CHECK_INT_GOTO(0, result);

	CHECK_UINT_GOTO(RDD_OK, rdd_writer_close(writer)); // to free resources
	remove("testoutput.E01");
	return 1;
error:
	remove("testoutput.E01");
	return 0;
}

static int 
test_ewf_close_writer_null()
{
	CHECK_UINT(RDD_BADARG, ewf_close(0));
	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_path_exists_path_null);
	TEST(test_path_exists_exists_info_null);
	TEST(test_path_exists_notexists_info_null);
	TEST(test_path_exists_true);
	TEST(test_path_exists_false);

	TEST(test_rdd_open_ewf_writer_writer_null);
	TEST(test_rdd_open_ewf_writer_path_null_no_overwrite);
	TEST(test_rdd_open_ewf_writer_path_null_overwrite);
	TEST(test_rdd_open_ewf_writer_path_null_overwrite_ask);	
	TEST(test_rdd_open_ewf_writer_hashcontainer_null);
	TEST(test_rdd_open_ewf_writer_compress_option_invalid_0);
	TEST(test_rdd_open_ewf_writer_compress_option_invalid_5);
	TEST(test_rdd_open_ewf_writer);
	TEST(test_rdd_open_ewf_writer_splitlen);	
	TEST(test_rdd_open_ewf_writer_splitlen_toosmall);
	TEST(test_rdd_open_ewf_writer_existing_no_overwrite);
	TEST(test_rdd_open_ewf_writer_existing_overwrite);
	TEST(test_rdd_open_ewf_writer_existing_overwrite_ask);

	TEST(test_ewf_write_zero_bytes);
	TEST(test_ewf_write_compression_best);
	TEST(test_ewf_write_compression_fast);
	TEST(test_ewf_write_compression_none);
	TEST(test_ewf_write_multiple);
	TEST(test_ewf_write_segments);

	TEST(test_compare_address_address_null);
	TEST(test_compare_address_result_null);
	TEST(test_compare_address_address_not_null);

	TEST(test_ewf_close_writer_null);
	return result;
}

TEST_MAIN;
