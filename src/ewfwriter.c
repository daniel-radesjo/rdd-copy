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



#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 2002-2004\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "rdd.h"
#include "writer.h"

#include "libewf.h"



/* Forward declarations
 */
static int ewf_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte);
static int ewf_close(RDD_WRITER *w);
static int ewf_compare_address(RDD_WRITER *w, struct addrinfo *address, int *result);

static RDD_WRITE_OPS ewf_write_ops = {
	ewf_write,
	ewf_close,
	ewf_compare_address
};

typedef struct _RDD_EWF_WRITER {
	char *path;
	libewf_handle_t * ewf_handle;
	RDD_HASH_CONTAINER * hashcontainer;
	int write_called;
} RDD_EWF_WRITER;



/* Check whether path is a valid path name in the file system.
 */
static int
path_exists(const char *path, struct stat *info)
{
	return stat(path, info) != -1 || errno != ENOENT;
}

static int
compress_level(int compression_type)
{
	// check if compression_type is empty-block (3)
	if(compression_type != 3){
		return compression_type;
	}
	return 0;
}

static int
compress_empty_block(int compression_type)
{
	if(compression_type == 3){
		return 0x01;
	}
	return 0x00;
}

/*
 * compression_type: 0 = no ewf, 1 = compression none, 2 compression full, 3 compression best, 4 empty-block
 */
int
rdd_open_ewf_writer(RDD_WRITER **self, const char *path,
			rdd_count_t splitlen, int compression_type, rdd_write_mode_t wmode, RDD_HASH_CONTAINER * hashcontainer)
{
	RDD_WRITER *w = 0;
	RDD_EWF_WRITER *state = 0;
	struct stat statinfo;
	int rc = RDD_OK;
	char *pathcopy = 0;
	char *pathcopy_without_extension = 0;
	uint8_t flags = libewf_get_flags_write();
	const char * EWF_EXTENSION = ".E01";
	int8_t compression_level = LIBEWF_COMPRESSION_NONE;
	uint8_t empty_block_compression = 0;
	// correct cause compression none = 0, compression full = 1, compression best = 2
	int corrected_compression_type = compression_type -1;


	if (self == 0) {
		rc = RDD_BADARG;
		return rc;
	}

	if (path == 0) {
		rc = RDD_BADARG;
		goto error;
	}

	if(corrected_compression_type < 0 || corrected_compression_type > 3){
		rc = RDD_BADARG;
		goto error;
	}

	if (hashcontainer == 0) {
		rc = RDD_BADARG;
		goto error;
	}

	if (splitlen != 0 && splitlen < RDD_EWF_MIN_SPLITLEN) {
		rc = RDD_BADARG;
		goto error;
	}	

	compression_level = compress_level(corrected_compression_type);
	empty_block_compression = compress_empty_block(corrected_compression_type);

	int pathsize_without_extension = strlen(path) + 1;
	int pathsize = pathsize_without_extension + strlen(EWF_EXTENSION);
	if ((pathcopy = malloc(pathsize)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	if (snprintf(pathcopy, pathsize, "%s%s", path, EWF_EXTENSION) > pathsize - 1) {
		/* shouldn't happen */
		rc = RDD_EOPEN;
		goto error;
	}

	if (wmode == RDD_NO_OVERWRITE && path_exists(pathcopy, &statinfo)) {
		rc = RDD_EEXISTS;
		goto error;
	}

	rc = rdd_new_writer(&w, &ewf_write_ops, sizeof(RDD_EWF_WRITER));
	if (rc != RDD_OK) {
		goto error;
	}
	state = (RDD_EWF_WRITER *) w->state;

	state->write_called = 0;
	state->path = pathcopy;


	/* Set the space for storing the hashcontainer */
	state->hashcontainer = hashcontainer;

	libewf_error_t *err = 0;

	if (libewf_handle_initialize(&state->ewf_handle, &err) == -1)
	{
		libewf_error_free(&err);
		rc = RDD_EOPEN;
		goto error;
	}

	if (state->ewf_handle == 0) {
		libewf_error_free(&err);
		rc = RDD_EOPEN;
		goto error;
	}

	if ((pathcopy_without_extension = malloc(pathsize_without_extension)) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}
	strcpy(pathcopy_without_extension, path);	
	char * filenames[1];
	filenames[0] = pathcopy_without_extension;	// libewf adds the extension

	if (libewf_handle_open(state->ewf_handle, filenames, 1, flags, &err) == -1)
	{
		libewf_error_free(&err);
		free(pathcopy_without_extension);
		rc = RDD_EOPEN;
		goto error;
	}
	free(pathcopy_without_extension);


	if (libewf_handle_set_format(state->ewf_handle, LIBEWF_FORMAT_ENCASE6, &err) == -1)
	{
		libewf_error_free(&err);
		rc = RDD_EOPEN;
		goto error;
	}

	if (libewf_handle_set_media_type(state->ewf_handle, LIBEWF_MEDIA_TYPE_FIXED, &err) == -1)
	{
		libewf_error_free(&err);
		rc = RDD_EOPEN;
		goto error;
	}

	if (libewf_handle_set_media_flags(state->ewf_handle, LIBEWF_MEDIA_FLAG_PHYSICAL, &err) == -1)
	{
		libewf_error_free(&err);
		rc = RDD_EOPEN;
		goto error;
	}

	if (libewf_handle_set_compression_values(state->ewf_handle, compression_level, empty_block_compression, &err) == -1)
	{
		libewf_error_free(&err);
		rc = RDD_EOPEN;
		goto error;
	}

	if (splitlen > 0) {
		if (libewf_handle_set_segment_file_size(state->ewf_handle, splitlen, &err) == -1)
		{
			libewf_error_free(&err);
			rc = RDD_EOPEN;
			goto error;
		}
	}

	*self = w;

	return RDD_OK;

error:


	*self = 0;
	if (pathcopy != 0) free(pathcopy);
	if (state != 0) {
		if (state->ewf_handle != 0) {
			libewf_handle_close(state->ewf_handle, &err);
			libewf_handle_free(&state->ewf_handle, &err);
		}
		free(state);
	}

	if (w != 0) free(w);
	return rc;
}

static int
ewf_write(RDD_WRITER *w, const unsigned char *buf, unsigned nbyte)
{

	/* For performance reasons, don't check the parameters */
	RDD_EWF_WRITER *state = w->state;

	libewf_error_t *err = 0;
	
	if (libewf_handle_write_buffer(state->ewf_handle, (void *)buf, nbyte, &err) == -1)
	{
		libewf_error_free(&err);
		return RDD_EWRITE;
	}
	if (nbyte > 0) {
		state->write_called = 1;
	}
	return RDD_OK;
}

static int
ewf_close(RDD_WRITER *self)
{
	int rc = RDD_OK;

	libewf_error_t *err = 0;

	if (self == 0) {
		return RDD_BADARG;
	}
	RDD_EWF_WRITER *state = self->state;

	uint8_t hashValue[RDD_MAX_DIGEST_LENGTH];
	memset(hashValue, 0, RDD_MAX_DIGEST_LENGTH);
	int present = 0;

	/* Pass the hashes to libewf */
	if (rdd_hash_present(state->hashcontainer, RDD_MD5, &present) == RDD_OK) {
		if (present) {
			if (rdd_get_hash(state->hashcontainer, RDD_MD5, hashValue) == RDD_OK) {
				if (libewf_handle_set_md5_hash(state->ewf_handle, hashValue, MD5_DIGEST_LENGTH, &err) == -1) {
					libewf_error_free(&err);
					rc = RDD_ECLOSE; // attempt to continue	
				}
			} 
		}
	} else {
		rc = RDD_ECLOSE; // attempt to continue
	}

	if (rdd_hash_present(state->hashcontainer, RDD_SHA1, &present) == RDD_OK) {
		if (present) {
			if (rdd_get_hash(state->hashcontainer, RDD_SHA1, hashValue) == RDD_OK) {
				if (libewf_handle_set_sha1_hash(state->ewf_handle, hashValue, SHA_DIGEST_LENGTH, &err) == -1) {
					libewf_error_free(&err);
					rc = RDD_ECLOSE; // attempt to continue	
				}
			} else {
				rc = RDD_ECLOSE; // attempt to continue	
			} 
		}
	} else {
		rc = RDD_ECLOSE; // attempt to continue
	}

	// ewf doesn't store any other hashes

	if (libewf_handle_write_finalize(state->ewf_handle, &err) == -1)
	{
		libewf_error_free(&err);
		rc = RDD_ECLOSE; // attempt to continue
	}

	if (libewf_handle_close(state->ewf_handle, &err) == -1)
	{
		libewf_error_free(&err);
		rc = RDD_ECLOSE; // attempt to continue	
	}

	if (libewf_handle_free(&state->ewf_handle, &err) == -1)
	{
		libewf_error_free(&err);
		rc = RDD_ECLOSE; // attempt to continue	
	}

	// set to read-only (see also safe writer, but this file only exists if write is actually called).
	if (state->write_called) {
		struct stat statinfo;
		if (stat(state->path, &statinfo) < 0) {
			return RDD_ECLOSE;
		}
	
		if (S_ISREG(statinfo.st_mode)
		&&  chmod(state->path, S_IRUSR|S_IRGRP|S_IROTH) < 0) {
			/* This need not be an error; we may not own
			* the output file.
			*/
		}
	}

	free(state->path);
	state->path = 0;

	return rc;
}

static int
ewf_compare_address(RDD_WRITER *self, struct addrinfo *address, int *result)
{

	if (self == 0) {
		return RDD_BADARG;
	}
	if (result == 0) {
		return RDD_BADARG;
	}
	// No address is attached to this type of writer, so only return true if the address is 0.
	*result = (address == 0);
	return RDD_OK;
}
