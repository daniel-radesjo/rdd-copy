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

#ifndef lint
static char copyright[] =
		"@(#) Copyright (c) 2002-2004\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rdd.h"
#include "reader.h"

#define MAX_LINE   128
#define MAX_FAULT    8

typedef unsigned short rngstate_t[3];
typedef unsigned long seed_t;

typedef struct _RDDFAULT
{
	rdd_count_t meanpos; /* mean read-error position (block offset) */
} RDDFAULT;

typedef struct _FAULTY_READER_STATE
{
	RDD_READER *parent;
	RDDFAULT faults[MAX_FAULT];
	unsigned nfault;
} FAULTY_READER_STATE;

/* Forward declarations
 */
static int
rdd_faulty_read(RDD_READER *r, unsigned char *buf, unsigned nbyte, unsigned *nread);
static int
rdd_faulty_tell(RDD_READER *r, rdd_count_t *pos);
static int
rdd_faulty_seek(RDD_READER *r, rdd_count_t pos);
static int
rdd_faulty_close(RDD_READER *r, int recurse);

static RDD_READ_OPS faulty_read_ops = { rdd_faulty_read, rdd_faulty_tell, rdd_faulty_seek,
		rdd_faulty_close };

static int
fault_compare(const void *p1, const void *p2)
{
	const RDDFAULT *f1 = p1;
	const RDDFAULT *f2 = p2;

	if (f1->meanpos < f2->meanpos)
	{
		return -1;
	}
	else if (f1->meanpos > f2->meanpos)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

static void
fault_init(RDDFAULT *f, rdd_count_t meanpos)
{
	memset(f, '\000', sizeof(*f));
	f->meanpos = meanpos;
}

/* Reads fault specifications from a configuration file.
 */
static int
read_faults(FILE *fp, FAULTY_READER_STATE *state)
{
	char line[MAX_LINE];
	unsigned lineno;
	rdd_count_t pos;

	for (lineno = 1; fgets(line, MAX_LINE, fp) != NULL; lineno++)
	{
		if (strlen(line) >= MAX_LINE - 1)
		{
			return RDD_ESYNTAX; /* line too long */
		}

		if (sscanf(line, "%llu", &pos) != 1)
		{
			return RDD_ESYNTAX; /* bad item count on line */
		}

		if (state->nfault >= MAX_FAULT)
		{
			return RDD_ESPACE; /* too many lines */
		}
		fault_init(&state->faults[state->nfault], pos);
		state->nfault++;
	}
	if (!feof(fp))
	{
		return RDD_ESYNTAX;
	}

	return RDD_OK;
}

/* Reads a list of fault specification from the configuration file.
 */
int
rdd_open_faulty_reader(RDD_READER **self, RDD_READER *parent, char *path)
{
	RDD_READER *r = 0;
	FAULTY_READER_STATE *state = 0;
	FILE *fp = 0;
	int rc;

	if (self == 0 || parent == 0 || path == 0)
	{
		return RDD_BADARG;
	}

	rc = rdd_new_reader(&r, &faulty_read_ops, sizeof(FAULTY_READER_STATE));
	if (rc != RDD_OK)
	{
		return rc;
	}

	if ((fp = fopen(path, "r")) == NULL)
	{
		free(r);
		return RDD_EOPEN;
	}

	state = (FAULTY_READER_STATE *) r->state;
	state->parent = parent;

	if ((rc = read_faults(fp, state)) != RDD_OK)
	{
		free(state);
		free(r);
		fclose(fp);
		return rc;
	}

	if (fclose(fp) == EOF)
	{
		free(state);
		free(r);
		return RDD_ECLOSE;
	}


	/* Sort fault specifications by mean fault position.
	 */
	qsort(state->faults, state->nfault, sizeof(RDDFAULT), &fault_compare);

	*self = r;
	return RDD_OK;

}

/* Simulates a faulty reader.
 * 
 * The algorithm is as follows.  For each user-specified fault
 * we have a location of occurrence and a (fixed) probability
 * of occurrence.  For each fault covered by the read request,
 * we check if the fault 'occurs' this time.  If none of the
 * covered faults occur, we pass the request to the parent reader.
 * Otherwise we select the fault with the lowest position and let
 * it occur.
 *
 * If a fault occurs, we still execute a partial read
 * up to the location of the fault.  This allows us to check
 * whether rdd's saving and restoring of the current file position
 * works all right: flt_read will return -1, but it will also
 * have modified the file position.
 */
int
rdd_faulty_read(RDD_READER *self, unsigned char *buf, unsigned nbyte, unsigned *nread)
{
	FAULTY_READER_STATE *state = self->state;
	rdd_count_t pos;
	RDDFAULT *f;
	unsigned i;
	int rc;

	if ((rc = rdd_reader_tell(state->parent, &pos)) != RDD_OK)
	{
		return rc;
	}

	for (i = 0; i < state->nfault; i++)
	{
		f = &state->faults[i];

		if (f->meanpos >= pos && f->meanpos < (pos + nbyte)) /* the position where the fault occurs. */
		{
			rc = rdd_reader_read(state->parent, buf, nbyte, nread);
			if (rc != RDD_OK)
			{
				return rc; /* Hmm, true read error */
			}

			if (f->meanpos < (pos + *nread))
			{
				/* The read result covers the fault. */
				return RDD_EREAD;
			}
			else
			{
				return RDD_OK;
			}
		}
	}

	/* No fault occurred; forward the read request to the parent reader.
	 */
	return rdd_reader_read(state->parent, buf, nbyte, nread);
}

int
rdd_faulty_tell(RDD_READER *self, rdd_count_t *pos)
{
	FAULTY_READER_STATE *state = self->state;

	return rdd_reader_tell(state->parent, pos);
}

int
rdd_faulty_seek(RDD_READER *self, rdd_count_t pos)
{
	FAULTY_READER_STATE *state = self->state;

	return rdd_reader_seek(state->parent, pos);
}

int
rdd_faulty_close(RDD_READER *self, int recurse)
{
	FAULTY_READER_STATE *state = self->state;

	if (recurse)
	{
		return rdd_reader_close(state->parent, 1);
	}
	else
	{
		return RDD_OK;
	}
}
