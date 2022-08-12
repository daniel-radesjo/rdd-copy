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

#include "mockstreamfilter.h"

#define STUB(s)(state->stubs.s)

#define TIMES(s,t)(state->expectations.s.invocations == t)

#define EXPECT(e)(state->expectations.e)

typedef struct _STUB_INPUT
{
	int retval;
} STUB_INPUT;

typedef struct _STUB_CLOSE
{
	int retval;
} STUB_CLOSE;

typedef struct _STUB_GET_RESULT
{
	int retval;
} STUB_GET_RESULT;

typedef struct _STUBS
{
	STUB_INPUT input;
	STUB_CLOSE close;
	STUB_GET_RESULT get_result;
} STUBS;

typedef struct _EXPECT_INPUT
{
	const unsigned char *buf;
	unsigned nbyte;
	int invocations;
} EXPECT_INPUT;

typedef struct _EXPECT_CLOSE
{
	int invocations;
} EXPECT_CLOSE;

typedef struct _EXPECT_GET_RESULT
{
	int invocations;
} EXPECT_GET_RESULT;

typedef struct _EXPECTATIONS
{
	EXPECT_INPUT input;
	EXPECT_CLOSE close;
	EXPECT_GET_RESULT get_result;
} EXPECTATIONS;

typedef struct _MOCKSTREAMFILTER_STATE
{
	STUBS stubs;
	EXPECTATIONS expectations;
} MOCKSTREAMFILTER_STATE;

static int mockstreamfilter_input(RDD_FILTER *f, const unsigned char *buf, unsigned nbyte);
static int mockstreamfilter_close(RDD_FILTER *f);
static int mockstreamfilter_get_result(RDD_FILTER *f, unsigned char *buf, unsigned nbyte);

static RDD_FILTER_OPS mockstreamfilter_ops = { mockstreamfilter_input, 0, mockstreamfilter_close, mockstreamfilter_get_result, 0 };

int
mockstreamfilter_open(RDD_FILTER **self)
{
	RDD_FILTER *f;
	MOCKSTREAMFILTER_STATE *state;
	int rc;

	rc = rdd_new_filter(&f, &mockstreamfilter_ops, sizeof(MOCKSTREAMFILTER_STATE), 0);
	if (rc != RDD_OK)
	{
		return rc;
	}

	state = (MOCKSTREAMFILTER_STATE *) f->state;

	*self = f;

	return RDD_OK;
}

static int
mockstreamfilter_input(RDD_FILTER *self, const unsigned char *buf, unsigned nbyte)
{
	MOCKSTREAMFILTER_STATE *state = self->state;

	EXPECT(input).buf = buf;
	EXPECT(input).nbyte = nbyte;
	EXPECT(input).invocations++;

	return STUB(input).retval;
}

void
mockstreamfilter_stub_input(RDD_FILTER *self, int retval)
{
	MOCKSTREAMFILTER_STATE *state = self->state;

	STUB(input).retval = retval;
}

int
mockstreamfilter_verify_input(RDD_FILTER *self, int times, const unsigned char *buf, unsigned nbyte)
{
	MOCKSTREAMFILTER_STATE *state = self->state;

	return TIMES(input, times) && EXPECT(input).buf == buf && EXPECT(input).nbyte == nbyte;
}

static int
mockstreamfilter_close(RDD_FILTER *self)
{
	MOCKSTREAMFILTER_STATE *state = self->state;

	EXPECT(close).invocations++;

	return STUB(close).retval;
}

void
mockstreamfilter_stub_close(RDD_FILTER *self, int retval)
{
	MOCKSTREAMFILTER_STATE *state = self->state;

	STUB(close).retval = retval;
}

int
mockstreamfilter_verify_close(RDD_FILTER *self, int times)
{
	MOCKSTREAMFILTER_STATE *state = self->state;

	return TIMES(close, times);
}

static int
mockstreamfilter_get_result(RDD_FILTER *self, unsigned char *buf, unsigned nbyte)
{

	MOCKSTREAMFILTER_STATE *state = self->state;

	EXPECT(get_result).invocations++;

	return STUB(get_result).retval;
}

void
mockstreamfilter_stub_get_result(RDD_FILTER *self, int retval)
{
	MOCKSTREAMFILTER_STATE *state = self->state;

	STUB(get_result).retval = retval;
}

int
mockstreamfilter_verify_get_result(RDD_FILTER *self, int times)
{
	MOCKSTREAMFILTER_STATE *state = self->state;

	return TIMES(get_result, times);
}
