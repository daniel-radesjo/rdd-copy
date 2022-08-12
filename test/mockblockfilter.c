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

#include "mockblockfilter.h"

#define STUB(s)(state->stubs.s)

#define TIMES(s,t)(state->expectations.s.invocations == t)

#define EXPECT(e)(state->expectations.e)

typedef struct _STUB_INPUT
{
	int retval;
} STUB_INPUT;

typedef struct _STUB_BLOCK
{
	int retval;
} STUB_BLOCK;

typedef struct _STUB_CLOSE
{
	int retval;
} STUB_CLOSE;

typedef struct _STUB_FREE
{
	int retval;
} STUB_FREE;

typedef struct _STUBS
{
	STUB_INPUT input;
	STUB_BLOCK block;
	STUB_CLOSE close;
	STUB_FREE free;
} STUBS;

typedef struct _EXPECT_INPUT
{
	const unsigned char **buf;
	unsigned *nbytes;
	int invocations;
} EXPECT_INPUT;

typedef struct _EXPECT_BLOCK
{
	unsigned *nbytes;
	int invocations;
} EXPECT_BLOCK;

typedef struct _EXPECT_CLOSE
{
	int invocations;
} EXPECT_CLOSE;

typedef struct _EXPECT_FREE
{
	int invocations;
} EXPECT_FREE;

typedef struct _EXPECTATIONS
{
	EXPECT_INPUT input;
	EXPECT_BLOCK block;
	EXPECT_CLOSE close;
	EXPECT_FREE free;
} EXPECTATIONS;

typedef struct _MOCKBLOCKFILTER_STATE
{
	STUBS stubs;
	EXPECTATIONS expectations;
} MOCKBLOCKFILTER_STATE;

static int
mockblockfilter_input(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte);
static int
mockblockfilter_block(RDD_FILTER *f, unsigned nbyte);
static int
mockblockfilter_close(RDD_FILTER *f);
static int
mockblockfilter_free(RDD_FILTER *f);

static RDD_FILTER_OPS mockblockfilter_ops = { mockblockfilter_input, mockblockfilter_block,
		mockblockfilter_close, 0, mockblockfilter_free };

int
mockblockfilter_open(RDD_FILTER **self, unsigned blocksize)
{
	RDD_FILTER *f;
	MOCKBLOCKFILTER_STATE *state;
	int rc;

	rc = rdd_new_filter(&f, &mockblockfilter_ops, sizeof(MOCKBLOCKFILTER_STATE), blocksize);
	if (rc != RDD_OK)
	{
		return rc;
	}

	state = (MOCKBLOCKFILTER_STATE *) f->state;

	*self = f;

	return RDD_OK;
}

static void *
block_copy(const void *data, size_t size)
{
	void *cpy = malloc(size);
	memcpy(cpy, data, size);
	return cpy;
}

static int
mockblockfilter_input(RDD_FILTER *self, const unsigned char *buf, unsigned nbyte)
{
	MOCKBLOCKFILTER_STATE *state = self->state;

	EXPECT(input).buf[EXPECT(input).invocations] = block_copy(buf, nbyte);
	EXPECT(input).nbytes[EXPECT(input).invocations] = nbyte;
	EXPECT(input).invocations++;

	return STUB(input).retval;
}

void
mockblockfilter_stub_input(RDD_FILTER *self, int retval, int times)
{
	MOCKBLOCKFILTER_STATE *state = self->state;

	EXPECT(input).buf = calloc(times, sizeof(unsigned char));
	EXPECT(input).nbytes = calloc(times, sizeof(unsigned));
	STUB(input).retval = retval;
}

int
mockblockfilter_verify_input(RDD_FILTER *self, int times, const unsigned char **buf,
		unsigned *nbytes)
{
	unsigned i;
	MOCKBLOCKFILTER_STATE *state = self->state;

	if(!(TIMES(input, times))){
		return 0;
	}

	unsigned int calls = EXPECT(input).invocations;

	for(i  = 0; i< calls; i++){
		if(EXPECT(input).nbytes[i] != nbytes[i]){
			return 0;
		}
		if(memcmp(EXPECT(input).buf[i], buf[i], nbytes[i])){
			return 0;
		}
	}
	return 1;
}

static int
mockblockfilter_block(RDD_FILTER *self, unsigned nbyte)
{
	MOCKBLOCKFILTER_STATE *state = self->state;

	EXPECT(block).nbytes[EXPECT(block).invocations] = nbyte;
	EXPECT(block).invocations++;

	return STUB(block).retval;
}

void
mockblockfilter_stub_block(RDD_FILTER *self, int retval, int times)
{
	MOCKBLOCKFILTER_STATE *state = self->state;

	EXPECT(block).nbytes = calloc(times, sizeof(unsigned));

	STUB(block).retval = retval;
}

int
mockblockfilter_verify_block(RDD_FILTER *self, int times, unsigned *nbytes)
{
	int i;
	MOCKBLOCKFILTER_STATE *state = self->state;

	unsigned calls = EXPECT(block).invocations;

	for(i = 0;i < calls; i++){
		if(EXPECT(block).nbytes[i] != nbytes[i]){
			return 0;
		}
	}

	return TIMES(block, times);
}

static int
mockblockfilter_close(RDD_FILTER *self)
{
	MOCKBLOCKFILTER_STATE *state = self->state;

	EXPECT(close).invocations++;

	return STUB(close).retval;
}

void
mockblockfilter_stub_close(RDD_FILTER *self, int retval)
{
	MOCKBLOCKFILTER_STATE *state = self->state;

	STUB(close).retval = retval;
}

int
mockblockfilter_verify_close(RDD_FILTER *self, int times)
{
	MOCKBLOCKFILTER_STATE *state = self->state;

	return TIMES(close, times);
}

static int
mockblockfilter_free(RDD_FILTER *self)
{

	MOCKBLOCKFILTER_STATE *state = self->state;

	EXPECT(free).invocations++;

	return STUB(free).retval;
}

void
mockblockfilter_stub_free(RDD_FILTER *self, int retval)
{
	MOCKBLOCKFILTER_STATE *state = self->state;

	STUB(free).retval = retval;
}

int
mockblockfilter_verify_free(RDD_FILTER *self, int times)
{
	MOCKBLOCKFILTER_STATE *state = self->state;

	return TIMES(free, times);

}
