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

#include "mockprinter.h"

#define STUB(s)(state->stubs.s)

#define TIMES(s,t)(state->expectations.s.invocations == t)

#define EXPECT(e)(state->expectations.e)

static void
mockprinter_print(RDD_MSGPRINTER *self, rdd_message_t mesg_type, int errcode, const char *mesg);
static int
mockprinter_close(RDD_MSGPRINTER *self, unsigned flags);

typedef struct _STUB_PRINT
{
	rdd_message_t mesg_type;
	int errorcode;
	const char *mesg;
} STUB_PRINT;

typedef struct _STUB_CLOSE
{
	int retval;
} STUB_CLOSE;

typedef struct _EXPECT_PRINT
{
	int invocations;
	rdd_message_t mesg_type;
	int errorcode;
	const char *mesg;

} EXPECT_PRINT;

typedef struct _EXPECT_CLOSE
{
	int invocations;
	int recurse;
} EXPECT_CLOSE;

typedef struct _STUBS
{
	STUB_PRINT print;
	STUB_CLOSE close;
} STUBS;

typedef struct _EXPECTATIONS
{
	EXPECT_PRINT print;
	EXPECT_CLOSE close;
} EXPECTATIONS;

typedef struct _MOCKPRINTER_STATE
{
	STUBS stubs;
	EXPECTATIONS expectations;
} MOCKPRINTER_STATE;

static RDD_MSGPRINTER_OPS mockprinter_ops = { mockprinter_print, mockprinter_close };

int
mockprinter_open(RDD_MSGPRINTER **self)
{
	RDD_MSGPRINTER *p;
	MOCKPRINTER_STATE *state;
	int rc;

	rc = rdd_mp_open_printer(&p, &mockprinter_ops, sizeof(MOCKPRINTER_STATE));
	if (rc != RDD_OK)
	{
		return rc;
	}

	state = (MOCKPRINTER_STATE *) p->state;

	*self = p;

	return RDD_OK;
}

static void
mockprinter_print(RDD_MSGPRINTER *self, rdd_message_t mesg_type, int errcode, const char *mesg)
{
	MOCKPRINTER_STATE *state = self->state;

	EXPECT(print).invocations++;

	EXPECT(print).mesg_type = mesg_type;
	EXPECT(print).errorcode = errcode;
	EXPECT(print).mesg = mesg;
}

int
mockprinter_verify_print(RDD_MSGPRINTER *self, int times, rdd_message_t mesg_type, int errorcode,
		const char *mesg)
{
	MOCKPRINTER_STATE *state = self->state;

	return TIMES(print, times) && EXPECT(print).mesg_type == mesg_type && EXPECT(print).errorcode
			== errorcode && (strcmp(EXPECT(print).mesg, mesg) == 0);

}

static int
mockprinter_close(RDD_MSGPRINTER *self, unsigned recurse)
{
	MOCKPRINTER_STATE *state = self->state;

	EXPECT(close).recurse = recurse;
	EXPECT(close).invocations++;

	return STUB(close).retval;
}

void
mockprinter_stub_close(RDD_MSGPRINTER *self, int retval)
{
	MOCKPRINTER_STATE *state = self->state;

	STUB(close).retval = retval;
}

int
mockprinter_verify_close(RDD_MSGPRINTER *self, int times, int recurse)
{
	MOCKPRINTER_STATE *state = self->state;

	return TIMES(close, times) && EXPECT(close).recurse == recurse;
}
