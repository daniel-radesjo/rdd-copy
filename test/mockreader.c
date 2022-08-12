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

#include "mockreader.h"

#define STUB(s)(state->stubs.s)

#define TIMES(s,t)(state->expectations.s.invocations == t)

#define EXPECT(e)(state->expectations.e)

typedef struct _STUB_READ
{
	unsigned char *buf;
	unsigned buf_size;
	int retval;
} STUB_READ;

typedef struct _STUB_TELL
{
	rdd_count_t pos;
	int retval;
} STUB_TELL;

typedef struct _STUB_SEEK
{
	int retval;
} STUB_SEEK;

typedef struct _STUB_CLOSE
{
	int retval;
} STUB_CLOSE;

typedef struct _STUBS
{
	STUB_READ read;
	STUB_TELL tell;
	STUB_SEEK seek;
	STUB_CLOSE close;
} STUBS;

typedef struct _EXPECT_READ
{
	int invocations;
	unsigned nbyte;
	unsigned nread;
} EXPECT_READ;

typedef struct _EXPECT_TELL
{
	int invocations;
} EXPECT_TELL;

typedef struct _EXPECT_SEEK
{
	rdd_count_t pos;
	int invocations;
} EXPECT_SEEK;

typedef struct _EXPECT_CLOSE
{
	int recurse;
	int invocations;
} EXPECT_CLOSE;

typedef struct _EXPECTATIONS
{
	EXPECT_READ read;
	EXPECT_TELL tell;
	EXPECT_SEEK seek;
	EXPECT_CLOSE close;
} EXPECTATIONS;

/** \brief Mock reader state.
 *
 */
typedef struct _MOCKREADER_STATE
{
	STUBS stubs;
	EXPECTATIONS expectations;
} MOCKREADER_STATE;

/* Forward declarations
 */
static int
mockreader_read(RDD_READER *r, unsigned char *buf, unsigned buf_size, unsigned *nread);
static int
mockreader_tell(RDD_READER *r, rdd_count_t *pos);
static int
mockreader_seek(RDD_READER *r, rdd_count_t pos);
static int
mockreader_close(RDD_READER *r, int recurse);

static RDD_READ_OPS mock_read_ops = { mockreader_read, mockreader_tell, mockreader_seek,
		mockreader_close };

int
mockreader_open(RDD_READER **self)
{
	RDD_READER *r = 0;
	MOCKREADER_STATE *state = 0;
	int rc = RDD_OK;

	rc = rdd_new_reader(&r, &mock_read_ops, sizeof(MOCKREADER_STATE));
	if (rc != RDD_OK)
	{
		*self = 0;
		return rc;
	}
	state = (MOCKREADER_STATE *) r->state;

	*self = r;
	return RDD_OK;
}

static int
mockreader_read(RDD_READER *self, unsigned char *buf, unsigned nbyte, unsigned *nread)
{
	MOCKREADER_STATE *state = self->state;

	unsigned char *test_buf = STUB(read).buf;

	unsigned ret_buf_size = (nbyte < STUB(read).buf_size) ? nbyte : STUB(read).buf_size;

	memcpy(buf, test_buf, ret_buf_size);

	*nread = ret_buf_size;

	EXPECT(read).invocations++;
	EXPECT(read).nbyte = nbyte;
	EXPECT(read).nread = ret_buf_size;

	return STUB(read).retval;
}

int
mockreader_verify_read(RDD_READER *self, int times, unsigned nbyte, unsigned nread)
{
	MOCKREADER_STATE *state = self->state;

	return TIMES(read, times) && EXPECT(read).nbyte == nbyte && EXPECT(read).nread == nread;
}

void
mockreader_stub_read(RDD_READER *self, unsigned char *buf, unsigned buf_size, int retval)
{
	MOCKREADER_STATE *state = self->state;

	STUB(read).buf = buf;
	STUB(read).buf_size = buf_size;
	STUB(read).retval = retval;
}

static int
mockreader_tell(RDD_READER *self, rdd_count_t *pos)
{
	MOCKREADER_STATE *state = self->state;

	EXPECT(tell).invocations++;
	*pos = STUB(tell).pos;
	return STUB(tell).retval;
}

void
mockreader_stub_tell(RDD_READER *self, rdd_count_t pos, int retval)
{
	MOCKREADER_STATE *state = self->state;

	STUB(tell).pos = pos;
	STUB(tell).retval = retval;
}

int
mockreader_verify_tell(RDD_READER *self, int times)
{
	MOCKREADER_STATE *state = self->state;

	return TIMES(tell,times);
}

static int
mockreader_seek(RDD_READER *self, rdd_count_t pos)
{
	MOCKREADER_STATE *state = self->state;

	EXPECT(seek).pos = pos;
	EXPECT(seek).invocations++;

	return STUB(seek).retval;
}

void
mockreader_stub_seek(RDD_READER *self, int retval)
{
	MOCKREADER_STATE *state = self->state;

	STUB(seek).retval = retval;
}

int
mockreader_verify_seek(RDD_READER *self, int times, rdd_count_t pos)
{
	MOCKREADER_STATE *state = self->state;

	return TIMES(seek, times) && EXPECT(seek).pos == pos;
}

static int
mockreader_close(RDD_READER *self, int recurse)
{
	MOCKREADER_STATE *state = self->state;

	EXPECT(close).recurse = recurse;
	EXPECT(close).invocations++;

	return STUB(close).retval;
}

void
mockreader_stub_close(RDD_READER *self, int retval)
{
	MOCKREADER_STATE *state = self->state;

	STUB(close).retval = retval;
}

int
mockreader_verify_close(RDD_READER *self, int times, int recurse)
{
	MOCKREADER_STATE *state = self->state;

	return TIMES(close, times) && (times == 0 || EXPECT(close).recurse == recurse);
}
