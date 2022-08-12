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



#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "msgprinter.h"

typedef struct _RDD_BCASTPRINTER_STATE {
	unsigned         nprinter;
	RDD_MSGPRINTER **printers;
} RDD_BCASTPRINTER_STATE;

static void bcastprinter_print(RDD_MSGPRINTER *self, rdd_message_t mesg_type, int errcode, const char *mesg);

static int  bcastprinter_close(RDD_MSGPRINTER *self, unsigned flags);

static RDD_MSGPRINTER_OPS bcast_ops = {
	bcastprinter_print,
	bcastprinter_close
};

int rdd_mp_open_bcastprinter(RDD_MSGPRINTER **self, unsigned nprinter, RDD_MSGPRINTER **printers)
{	
	RDD_MSGPRINTER *p = 0;
	RDD_BCASTPRINTER_STATE *state = 0;
	RDD_MSGPRINTER **printertab = 0;
	int rc;
	unsigned i;

	*self = 0;

	if(printers == NULL){
		return RDD_BADARG;
	}

	printertab = malloc(nprinter * sizeof(RDD_MSGPRINTER *));
	if (printertab == 0) {
		return RDD_NOMEM;
	}
	for (i = 0; i < nprinter; i++) {
		printertab[i] = printers[i];
	}

	rc = rdd_mp_open_printer(&p, &bcast_ops, sizeof(RDD_BCASTPRINTER_STATE));
	if (rc != RDD_OK) {
		free(printertab);
		return rc;
	}

	state = (RDD_BCASTPRINTER_STATE *) p->state;
	state->nprinter = nprinter;
	state->printers = printertab;

	*self = p;
	return RDD_OK;
}

static void bcastprinter_print(RDD_MSGPRINTER *self, rdd_message_t mesg_type, int errcode, const char *mesg)
{
	RDD_BCASTPRINTER_STATE *bcast = (RDD_BCASTPRINTER_STATE *) self->state;
	unsigned i;

	for (i = 0; i < bcast->nprinter; i++) {
		rdd_mp_message(bcast->printers[i], mesg_type, "%s", mesg);
	}
}

static int bcastprinter_close(RDD_MSGPRINTER *self, unsigned flags) {
	RDD_BCASTPRINTER_STATE *state = (RDD_BCASTPRINTER_STATE *) self->state;
	unsigned i;
	int rc;

	if ((flags & RDD_MP_RECURSE) != 0) {
		for (i = 0; i < state->nprinter; i++) {
			rc = rdd_mp_close(state->printers[i], flags);
			if (rc != RDD_OK) {
				return rc;
			}
		}
	}

	free(state->printers);
	memset(state, 0, sizeof *state);
	return RDD_OK;
}
