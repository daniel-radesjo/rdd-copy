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


#ifndef MOCKREADER_H_
#define MOCKREADER_H_

#include "rdd.h"
#include "reader.h"
#include <string.h>
#include <stdio.h>

int mockreader_open(RDD_READER **self);

void mockreader_stub_read(RDD_READER *self, unsigned char *buf, unsigned buf_size, int retval);

int mockreader_verify_read(RDD_READER *self, int times, unsigned nbtye, unsigned nread);

void mockreader_stub_tell(RDD_READER *self, rdd_count_t pos, int retval);

int mockreader_verify_tell(RDD_READER *self, int times);

void mockreader_stub_seek(RDD_READER *self, int retval);

int mockreader_verify_seek(RDD_READER *self, int times, rdd_count_t pos);

void mockreader_stub_close(RDD_READER *self, int recurse);

int mockreader_verify_close(RDD_READER *self, int times, int recurse);

#endif /* MOCKREADER_H_ */

