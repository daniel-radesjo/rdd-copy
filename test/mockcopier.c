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

#include "mockcopier.h"

#define STUB(s)(state->stubs.s)

#define TIMES(s,t)(state->expectations.s.invocations == t)

#define EXPECT(e)(state->expectations.e)

typedef struct _STUB_COPY_EXEC
{
	int retval;
} STUB_COPY_EXEC;

typedef struct _EXPECT_COPY_EXEC
{
	RDD_READER *rdd_reader;
	RDD_FILTERSET *filter_set;
	RDD_COPIER_RETURN *copier_return;
	int invocations;
} EXPECT_COPY_EXEC;

typedef struct _STUBS
{
	STUB_COPY_EXEC copy_exec;
} STUBS;

typedef struct _EXPECTATIONS
{
	EXPECT_COPY_EXEC copy_exec;
} EXPECTATIONS;

typedef struct _MOCKCOPIER_STATE
{
	STUBS stubs;
	EXPECTATIONS expectations;
} MOCKCOPIER_STATE;

static int
mockcopier_copy_exec(RDD_COPIER *c, RDD_READER *reader, RDD_FILTERSET *fset, RDD_COPIER_RETURN *ret);

static RDD_COPY_OPS mockcopier_ops = { mockcopier_copy_exec, 0 };

int
mockcopier_open(RDD_COPIER **self)
{
	RDD_COPIER *c = 0;
	MOCKCOPIER_STATE *state = 0;
	int rc;

	rc = rdd_new_copier(&c, &mockcopier_ops, sizeof(MOCKCOPIER_STATE));
	if (rc != RDD_OK)
	{
		return rc;
	}

	state = (MOCKCOPIER_STATE *) c->state;
	*self = c;

	return RDD_OK;
}

static int
mockcopier_copy_exec(RDD_COPIER *self, RDD_READER *reader, RDD_FILTERSET *fset, RDD_COPIER_RETURN *ret)
{
	MOCKCOPIER_STATE *state = self->state;

	EXPECT(copy_exec).rdd_reader = reader;
	EXPECT(copy_exec).filter_set = fset;
	EXPECT(copy_exec).copier_return = ret;

	EXPECT(copy_exec).invocations++;

	return STUB(copy_exec).retval;
}

void
mockcopier_stub_copy_exec(RDD_COPIER *self, int retval)
{
	MOCKCOPIER_STATE *state = self->state;

	STUB(copy_exec).retval = retval;
}

int
mockcopier_verify_copy_exec(RDD_COPIER *self, int times, RDD_READER *reader, RDD_FILTERSET *fset, RDD_COPIER_RETURN *ret)
{
	MOCKCOPIER_STATE *state = self->state;

	return TIMES(copy_exec, times) && EXPECT(copy_exec).copier_return == ret && EXPECT(copy_exec).rdd_reader == reader && EXPECT(copy_exec).filter_set == fset;
}

