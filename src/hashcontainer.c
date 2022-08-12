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

#include <stdlib.h>
#include <string.h>

#include "hashcontainer.h"
#include "rdd.h"

int rdd_new_hashcontainer(RDD_HASH_CONTAINER ** self)
{
	RDD_HASH_CONTAINER * h = 0;
	int rc = RDD_OK;

	if (self == 0) {
		return RDD_BADARG;
	}

	if ((h = calloc(1, sizeof(RDD_HASH_CONTAINER))) == 0) {
		rc = RDD_NOMEM;
		goto error;
	}

	*self = h;
	return RDD_OK;

error:
	*self = 0;
	if (h != 0) free(h);
	return rc;

}

int rdd_set_hash(RDD_HASH_CONTAINER * self, const char * hash_type, const uint8_t * hash)
{
	if (self == 0) {
		return RDD_BADARG;
	}
	if (hash_type == 0) {
		return RDD_BADARG;
	}
	if (hash == 0) {
		return RDD_BADARG;
	}

	if (!strcmp(hash_type, RDD_MD5)) {
		self->md5present = 1;
		memcpy(self->md5hash, hash, MD5_DIGEST_LENGTH);
	} else if (!strcmp(hash_type, RDD_SHA1)) {
		self->sha1present = 1;
		memcpy(self->sha1hash, hash, SHA_DIGEST_LENGTH);
	} else if (!strcmp(hash_type, RDD_SHA256)) {
		self->sha256present = 1;
		memcpy(self->sha256hash, hash, SHA256_DIGEST_LENGTH);
	} else if (!strcmp(hash_type, RDD_SHA384)) {
		self->sha384present = 1;
		memcpy(self->sha384hash, hash, SHA384_DIGEST_LENGTH);
	} else if (!strcmp(hash_type, RDD_SHA512)) {
		self->sha512present = 1;
		memcpy(self->sha512hash, hash, SHA512_DIGEST_LENGTH);
	} else {
		return RDD_BADARG;
	}

	return RDD_OK;
}

int rdd_get_hash(RDD_HASH_CONTAINER * self, const char * hash_type, uint8_t * hash)
{
	if (self == 0) {
		return RDD_BADARG;
	}
	if (hash_type == 0) {
		return RDD_BADARG;
	}
	if (hash == 0) {
		return RDD_BADARG;
	}

	if (!strcmp(hash_type, RDD_MD5)) {
		if (!self->md5present) {
			return RDD_NOTFOUND;
		}
		memcpy(hash, self->md5hash, MD5_DIGEST_LENGTH);
	} else if (!strcmp(hash_type, RDD_SHA1)) {
		if (!self->sha1present) {
			return RDD_NOTFOUND;
		}
		memcpy(hash, self->sha1hash, SHA_DIGEST_LENGTH);
	} else if (!strcmp(hash_type, RDD_SHA256)) {
		if (!self->sha256present) {
			return RDD_NOTFOUND;
		}
		memcpy(hash, self->sha256hash, SHA256_DIGEST_LENGTH);
	} else if (!strcmp(hash_type, RDD_SHA384)) {
		if (!self->sha384present) {
			return RDD_NOTFOUND;
		}
		memcpy(hash, self->sha384hash, SHA384_DIGEST_LENGTH);
	} else if (!strcmp(hash_type, RDD_SHA512)) {
		if (!self->sha512present) {
			return RDD_NOTFOUND;
		}
		memcpy(hash, self->sha512hash, SHA512_DIGEST_LENGTH);
	} else {
		return RDD_BADARG;
	}

	return RDD_OK;

}

int rdd_hash_present(RDD_HASH_CONTAINER * self, const char * hash_type, int * present)
{
	if (self == 0) {
		return RDD_BADARG;
	}
	if (hash_type == 0) {
		return RDD_BADARG;
	}
	if (present == 0) {
		return RDD_BADARG;
	}

	if (!strcmp(hash_type, RDD_MD5)) {
		*present = self->md5present;
	} else if (!strcmp(hash_type, RDD_SHA1)) {
		*present = self->sha1present;
	} else if (!strcmp(hash_type, RDD_SHA256)) {
		*present = self->sha256present;
	} else if (!strcmp(hash_type, RDD_SHA384)) {
		*present = self->sha384present;
	} else if (!strcmp(hash_type, RDD_SHA512)) {
		*present = self->sha512present;
	} else {
		return RDD_BADARG;
	}	


	return RDD_OK;
}
