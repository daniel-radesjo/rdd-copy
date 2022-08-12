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


/*
 * $Author: raoul $
 * $LastChangedBy: kojak $
 * $LastChangedDate: 2003-01-02 19:32:23 +0100 (Thu, 02 Jan 2003) $
 */

#ifndef lint
static char copyright[] =
"@(#) Copyright (c) 2002\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"
#include "error.h"
#include "commandline.h"

static const char *usage_message;

void
rdd_opt_init(const char *usage_msg)
{
	usage_message = usage_msg;
}

static int
match_name(char *input, char *short_name, char *long_name)
{
	// protect against null pointer
	if (input == 0) {
		return 0;
	}
	// only compare short name when it's present
	if (short_name != 0) {
		if (!strcmp(input, short_name)) {
			return 1;
		}
	}

	// only compare long name when it's present
	if (long_name != 0) {
		if (!strcmp(input, long_name)) {
			return 1;
		}
	}

	return 0;
}

/* Verify whether argv[*i] is an option name (short or long) and
 * whether its argument, if any, is present.
 */
RDD_OPTION *
rdd_get_opt_with_arg(RDD_OPTION * tab, char **argv, int argc, unsigned *i, char **opt, char **arg)
{
	RDD_OPTION *od;
	char *optname;

	if (tab == 0) {
		return 0;
	}
	if (argv == 0) {
		return 0;
	}
	if (argc <= 0) {
		return 0;
	}
	if (i == 0) {
		return 0;
	}
	if (*i >= argc) {
		return 0;
	}
	if (*i < 0) {
		return 0;
	}
	if (opt == 0) {
		return 0;
	}
	if (arg == 0) {
		return 0;
	}	
		

	*opt = 0;
	*arg = 0;
	optname = argv[*i];
	for (od = &tab[0]; od->long_name != 0; od++) {

		if (!match_name(optname, od->short_name, od->long_name)) {
			continue;
		}
		++od->count;
		*opt = optname;
		/* special treatment for output parameters -- can occur multiple times */
		if (!strcmp(od->long_name, "--out")) {
			*arg = 0;
		} else {
			if (od->count > 1) {
				error("option %s specified multiple times", optname);
			}
	
			*opt = optname;
			if (od->arg_descr == 0) {	/* no argument */
				*arg = 0;
			} else {
				(*i)++;
				if ((*i) >= (unsigned) argc) {
					error("option %s requires an argument", optname);
				}
				od->arg_value = *arg = argv[*i];
			}
		}
		return od;
	}
	return 0;
}

int
rdd_opt_set_arg(RDD_OPTION * tab, char * longname, char ** argp)
{
	RDD_OPTION *od;

	if (tab == 0) {
		return 0;
	}
	if (longname == 0) {
		return 0;
	}

	for (od = &tab[0]; od->long_name != 0; od++) {
		if (streq(od->long_name+2, longname)) {
		       	if (od->count == 0) {
				return 0;	/* option not set */
			}
			if (argp != 0) {
				*argp = od->arg_value;
			}
			return 1;
		}
	}
	bug("opt_set_arg: %s is not a known option", longname);
	return 0; /* NOTREACHED */
}

int
rdd_opt_set(RDD_OPTION * tab, char *longname)
{
	return rdd_opt_set_arg(tab, longname, 0);
}

static void 
rdd_option_table_usage(RDD_OPTION * tab, const char * name)
{
	RDD_OPTION *od;
	char optnames[80];

	if (name == 0 || tab == 0) {
		exit(EXIT_FAILURE);
	}

	for (od = &tab[0]; od->long_name != 0; od++) {
		if (od->short_name != 0) {
			snprintf(optnames, sizeof optnames, "%s, %s %s",
				od->short_name, od->long_name,
				od->arg_descr == 0 ? "" : od->arg_descr);
		} else {
			snprintf(optnames, sizeof optnames, "%s %s", od->long_name,
				od->arg_descr == 0 ? "" : od->arg_descr);
		}
		optnames[(sizeof optnames)-1] = '\000';

		if (strlen(optnames) <= 32) {
			fprintf(stderr, "%-32.32s %s\n",
					optnames, od->description);
		} else {
			fprintf(stderr, "%s\n", optnames);
			fprintf(stderr, "%-32.32s %s\n", "", od->description);
		}
	}	
}

void
rdd_opt_usage(RDD_OPTION * opttab, RDD_OPTION * output_opttab, int exitCode)
{
	if (usage_message != 0) {
		fprintf(stderr, "Usage: %s", usage_message);
	}

	if (opttab != 0) {
		rdd_option_table_usage(opttab, "Options");
	}

	if (output_opttab != 0) {
		rdd_option_table_usage(output_opttab, "Output options");
	}
	exit(exitCode);
}

int
compare_paths(char *first_path, char *second_path)
{
	struct stat buffer;
	int status, fildes;
	long long first, second;
	fildes = open(first_path, O_RDONLY);
	if (fildes != -1) {
		status = fstat(fildes, &buffer);
		first = buffer.st_ino;
		close(fildes);
		fildes = open(second_path, O_RDONLY);
		if (fildes != -1) {
			status = fstat(fildes, &buffer);
			second = buffer.st_ino;
			close(fildes);
			return !(second == first);
		}
	}
	return 1;
}



