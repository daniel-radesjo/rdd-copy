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

#ifndef __rdd_hashcontainer_h__
#define __rdd_hashcontainer_h__

#include <stdint.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_OPENSSL
#include <openssl/md5.h>
#include <openssl/sha.h>
#endif /* HAVE_OPENSSL */


#define RDD_MAX_DIGEST_LENGTH       SHA512_DIGEST_LENGTH		/* bytes */

static const char RDD_MD5[] = "MD5";
static const char RDD_SHA1[] = "SHA1";
static const char RDD_SHA256[] = "SHA256";
static const char RDD_SHA384[] = "SHA384";
static const char RDD_SHA512[] = "SHA512";

typedef struct _RDD_HASH_CONTAINER
{
	int md5present;
	uint8_t md5hash[MD5_DIGEST_LENGTH];
	int sha1present;
	uint8_t sha1hash[SHA_DIGEST_LENGTH];
	int sha256present;
	uint8_t sha256hash[SHA256_DIGEST_LENGTH];
	int sha384present;
	uint8_t sha384hash[SHA384_DIGEST_LENGTH];
	int sha512present;
	uint8_t sha512hash[SHA512_DIGEST_LENGTH];
} RDD_HASH_CONTAINER;


/** \brief Creates an object for storing hashes.
 *  \param self output value: the new hashcontainer.
 *  \return Returns \c RDD_OK on success.
 *
 * Routine \c rdd_new_hashes() creates a new hashcontainer object.
 */
int rdd_new_hashcontainer(RDD_HASH_CONTAINER ** self);

/** \brief Stores a specific hash in the hashcontainer.
 *  \param self a pointer to the hashcontainer.
 *  \param hash_type a null-terminated string containing the hash name (md5 or sha-1, 256, 384, or 512).
 *  \param hash the hash itself. It is assumed that sufficient space is available in hash (..._DIGEST_LENGTH).
 *  \return Returns \c RDD_OK on success.
 *
 * Routine \c rdd_set_hash() stores a hash in the hashcontainer.
 */
int rdd_set_hash(RDD_HASH_CONTAINER * self, const char * hash_type, const uint8_t * hash); 

/** \brief Retrieves a specific hash from the hashcontainer.
 *  \param self a pointer to the hashcontainer.
 *  \param hash_type a null-terminated string containing the hash name (md5 or sha-1, 256, 384, or 512).
 *  \param hash output value: space for storing the hash. It is assumed that sufficient space is available in hash (..._DIGEST_LENGTH).
 *  \return Returns \c RDD_OK on success; returns \c RDD_NOTFOUND if the hash has not been storedin the hashcontainer.
 *  \note .
 *
 * Routine \c rdd_get_hash() retrieves a hash from the hashcontainer.
 */
int rdd_get_hash(RDD_HASH_CONTAINER * self, const char * hash_type, uint8_t * hash); 

/** \brief Checks if a specific hash is present in the hashcontainer.
 *  \param self a pointer to the hashcontainer.
 *  \param hash_type a null-terminated string containing the hash name (md5 or sha-1, 256, 384, or 512). 
 *  \param hash output value: will be 1 if the hash is present, 0 if it's not.
 *  \return Returns \c RDD_OK on success.
 *  \note .
 *
 * Routine \c rdd_hash_present() checks if a specific hash is present in the hash container.
 */
int rdd_hash_present(RDD_HASH_CONTAINER * self, const char * hash_type, int * present);
#endif /* __rdd_hashcontainer_h__ */
