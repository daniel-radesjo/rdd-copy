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
"@(#) Copyright (c) 2002-2004\n\
	Netherlands Forensic Institute.  All rights reserved.\n";
#endif /* not lint */


/*
 * This program, rdd, copies data from one file to another. It is
 * more robust with respect to read errors than most Unix utilities.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "rdd.h"
#include "rdd_internals.h"


/* PLEASE keep the includes for crypto.h and zlib.h in this- ttcpwriter crashes when running the tests; modified tcpwriter.c such that getaddrinfo takes the port as a string.
 * order (crypto.h first); zlib.h introduces a typedef (free_func)
 * that conflicts with a parameter name in crypto.h.  This problem
 * occurs only in older versions.
 */
#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
#endif
#if defined(HAVE_LIBZ)
#include <zlib.h>
#else
#error Sorry, need libz to compile
#endif

#include "numparser.h"
#include "reader.h"
#include "commandline.h"
#include "error.h"
#include "hashcontainer.h"
#include "writer.h"
#include "filter.h"
#include "filterset.h"
#include "copier.h"
#include "netio.h"
#include "progress.h"
#include "msgprinter.h"

#define DEFAULT_BLOCK_LEN	    262144	/* bytes */
#define DEFAULT_MIN_BLOCK_SIZE	     32768	/* bytes */
#define DEFAULT_HIST_BLOCK_SIZE	    262144	/* bytes */
#define DEFAULT_CHKSUM_BLOCK_SIZE    32768	/* bytes */
#define DEFAULT_BLOCKMD5_SIZE         4096	/* bytes */

#define DEFAULT_NRETRY               1
#define DEFAULT_RECOVERY_LEN	     4	/* read blocks */
#define DEFAULT_MAX_READ_ERR	     0	/* 0 = infinity */
#define DEFAULT_RDD_SERVER_PORT       4832

#define bool2str(b)   ((b) ? "yes" : "no")
#define str2str(s)    ((s) == 0? "<none>" : (s))

/* Mode bits
 */
typedef enum _rdd_copy_mode_t {
	RDD_LOCAL  = 0x1,	/* read file, write file */
	RDD_CLIENT = 0x2,	/* read file, write network */
	RDD_SERVER = 0x4	/* read network, write file */
} rdd_copy_mode_t;

#define ALL_MODES (RDD_LOCAL|RDD_CLIENT|RDD_SERVER)

#define RDD_MAX_OUTPUT_OPTS 16

typedef struct _rdd_output_opt_t {
	int 	 	ewf;			/* output as ewf?, 0 = no, 1 ewf none, 2 ewf fast, 3 ewf best, 4 ewf empty-block */
	rdd_count_t  	splitlen;		/* create new output file every splitlen bytes */
	char     	*outpath;		/* output file or its prefix */
	char     	*server_host;		/* host name of rdd server */
	unsigned int 	server_port;		/* TCP port of rdd server */
} rdd_output_opt_t;

/* rdd's command-line arguments
 */
typedef struct _rdd_copy_opts {
	int       compress;		/* compression enabled? */
	int       quiet;		/* batch mode (no questions)? */
	char     *infile;		/* input file (source of copy) */
	char     *logfile;		/* log file */
	char     *simfile;		/* read-fault simulation config file */
	char     *crc32file;		/* output file for CRC32 checksums */
	char     *adler32file;		/* output file for Adler32 checksums */
	char     *histfile;		/* output file for histogram stats */
	char     *blockmd5file;		/* output file for blockwise MD5 */
	int       verbose;		/* Be verbose? */
	int       raw;			/* Reading from a raw device? */
	unsigned  mode;			/* local, client, or server mode */
	unsigned int server_port;	/* TCP port of rdd server (only used on server side) */
	int       inetd;		/* read from file desc. 0? */
	int       force_overwrite;	/* output overwrites existing files */
	int       md5;			/* MD5-hash all data? */
	int       sha1;			/* SHA1-hash all data? */
	int       sha256;		/* SHA256-hash all data? */
	int       sha384;		/* SHA384-hash all data? */
	int       sha512;		/* SHA512-hash all data? */
	unsigned  nretry;		/* Max. # read retries for bad blocks */
	rdd_count_t  blocklen;		/* default copy-block size */
	rdd_count_t  adler32len;	/* block size for Adler32 */
	rdd_count_t  crc32len;		/* block size for CRC32 */
	rdd_count_t  histblocklen;	/* histogramming block size */
	rdd_count_t  blockmd5len;	/* block size for block-wise MD5 */
	rdd_count_t  minblocklen;	/* unit of data loss */
	rdd_count_t  offset;		/* start copying here */
	rdd_count_t  count;		/* copy this many bytes */
	unsigned int output_count;	/* the number of output files */
	rdd_output_opt_t output[RDD_MAX_OUTPUT_OPTS];	/* the output options list */
	rdd_count_t  progresslen;	/* progress reporting interval (s) */
	rdd_count_t  max_read_err;	/* Max. # read errors allowed */
} rdd_copy_opts;

static rdd_copy_opts  opts;

static char* compression_types[] = { "no ewf", "none", "fast", "best", "empty-block", NULL};

static char* usage_message = "\n"
	"\trdd-copy [local options] --in infile --out <output options>\n"
	"\trdd-copy -C [client options] --in infile --out <output options>\n"
	"\trdd-copy -S [server options]\n";

static RDD_OPTION opttab[] = {
        {"-?",				"--help",			0,			ALL_MODES,		"Print this message",					0,	0},
        {0,				"--sha1",			0,			ALL_MODES,		"Compute and print SHA1 hash",				0,	0},
	{0,				"--sha256",			0,			ALL_MODES,		"Compute and print SHA256 hash",			0,	0},
	{0,				"--sha384",			0,			ALL_MODES,		"Compute and print SHA384 hash",			0,	0},
	{0,				"--sha512",			0,			ALL_MODES,		"Compute and print SHA512 hash",			0,	0},
        {0,				"--md5",			0,			ALL_MODES,		"Compute and print MD5 hash",				0,	0},
        {"-A",				"--adler32",			"<file>",		ALL_MODES,		"Compute and store Adler32 checksums in <file>",	0,	0},
        {"-a",				"--adler32-block-size",		"<size>",		ALL_MODES,		"Adler32 uses <size>-byte blocks",			0,	0},
        {"-b",				"--block-size",			"<count>[kKmMgG]",	RDD_LOCAL|RDD_CLIENT,	"Read blocks of <count> [KMG]byte at a time",		0,	0},
        {"-C",				"--client",			0,			0,			"Run rdd as a network client",				0,	0},
        {"-c",				"--count",			"<count>[kKmMgG]",	ALL_MODES,		"Read at most <count> [KMG]bytes",			0,	0},
        {0,				"--block-md5",			"<file>",		ALL_MODES,		"Store block-wise MD5 hash values in <file>",		0,	0},
        {0,				"--block-md5-size",		"<size>",		ALL_MODES,		"block-wise MD5 block size",				0,	0},
        {"-F",				"--fault-simulation",		"<file>",		RDD_LOCAL|RDD_CLIENT,	"simulate read errors specified in <file>",		0,	0},
        {"-f",				"--force",			0,			ALL_MODES,		"Ruthlessly overwrite existing files (including log file)",			0,	0},
        {"-H",				"--histogram",			"<file>",		ALL_MODES,		"Store histogram-derived stats in <file>",		0,	0},
        {"-h",				"--histogram-block-size",	"<size>",		ALL_MODES,		"Histogramming block size",				0,	0},
        {"-i",				"--inetd",			0,			RDD_SERVER,		"rdd is started by (x)inetd",				0,	0},
        {"-l",				"--log-file",			"<file>",		ALL_MODES,		"Log messages in <file>",				0,	0},
        {"-M",				"--max-read-err",		"<count>",		RDD_LOCAL|RDD_CLIENT,	"Give up after <count> read errors",			0,	0},
        {"-m",				"--min-block-size",		"<count>[kKmMgG]",	RDD_LOCAL|RDD_CLIENT,	"Minimum read-block size is <count> [KMG]byte",		0,	0},
        {"-n",				"--nretry",			"<count>",		RDD_LOCAL|RDD_CLIENT,	"Retry failed reads <count> times",			0,	0},
        {"-o",				"--offset",			"<count>[kKmMgG]",	ALL_MODES,		"Skip <count> [KMG] input bytes",			0,	0},
        {"-P",				"--progress",			"<sec>",		ALL_MODES,		"Report progress every <sec> seconds",			0,	0},
        {"-p",				"--port",			"<portnum>",		RDD_SERVER,		"Set server port to <port>",				0,	0},
        {"-q",				"--quiet",			0,			ALL_MODES,		"Do not ask questions",					0,	0},
        {"-r",				"--raw",			0,			RDD_LOCAL|RDD_CLIENT,	"Read from a raw device (/dev/raw/raw[0-9])",		0,	0},
        {"-S",				"--server",			0,			0,			"Run rdd as a network server",				0,	0},
        {0,				"--crc32",			"<file>",		ALL_MODES,		"Compute and store CRC32 checksums in <file>",		0,	0},
        {0,				"--crc32-block-size",		"<size>",		ALL_MODES,		"CRC32 uses <size>-byte blocks",			0,	0},
        {"-V",				"--version",			0,			ALL_MODES,		"Report version number and exit",			0,	0},
        {"-v",				"--verbose",			0,			ALL_MODES,		"Be verbose",						0,	0},
        {"-z",				"--compress",			0,			RDD_CLIENT,		"Compress data sent across the network",		0,	0},
        {"-I",				"--in",				"<file>",		RDD_LOCAL|RDD_CLIENT,	"Use <file> as input file"			,	0,	0},
        {"-O",				"--out",			"<output options>",	RDD_LOCAL|RDD_CLIENT,	"Output using <output options> (can be used multiple times)",	0,	0},
        {0,				0,				0,			0,			0,							0,	0} /* sentinel */
};

static RDD_OPTION output_opttab[] = {
		{"-e", 				"--ewf",			"<compression>",RDD_LOCAL|RDD_CLIENT,	"Output as Expert Witness Compression Format (EnCase), compression: none, fast, best, empty-block",	0,	0},
        {"-s",				"--split",			"<count>[kKmMgG]",	RDD_LOCAL|RDD_CLIENT,	"Split output,	all files < <count> [KMG]bytes",	0,	0},
	{"-N", 				"--name",			"<file>",		RDD_LOCAL|RDD_CLIENT, 	"The output file name",					0,	0},
        {"-p",				"--port",			"<portnum>",		RDD_CLIENT,		"Set server port to <port>",				0,	0},
        {0,				0,				0,			0,			0,							0,	0} /* sentinel */
};

#define RDD_OUTPUT_OPTTAB_OPTION_COUNT sizeof(output_opttab)/sizeof(RDD_OPTION)

static RDD_OPTION all_output_opttabs[RDD_OUTPUT_OPTTAB_OPTION_COUNT * RDD_MAX_OUTPUT_OPTS];

static RDD_MSGPRINTER *the_printer;

static void
fatal_rdd_error(int rdd_errno, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdd_mp_vrddmsg(the_printer, RDD_MSG_ERROR, rdd_errno, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

static void
logmsg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	rdd_mp_vmessage(the_printer, RDD_MSG_INFO, fmt, ap);
	va_end(ap);
}

/* Wrappers around the number-parsing routines.
 */
static rdd_count_t
scan_size(char *str, unsigned flags)
{
	rdd_count_t sz;
	int rc;

	if ((rc = rdd_parse_bignum((const char *) str, flags, &sz)) != RDD_OK) {
		fatal_rdd_error(rc, "bad number %s", str);
	}
	return sz;
}

static int
check_compress_option(char *arg)
{
	int i;

	// start at 1, 0 is without ewf
	for(i = 1; compression_types[i]; i++){
		if(strcmp(compression_types[i], arg) == 0){
			return i;
		}
	}
	fatal_rdd_error(RDD_BADARG, "unknown ewf compression %s\n", arg);

	return -1;
}

static char *
print_ewf_compress_option()
{
	int ewf = opts.output[0].ewf;
	if(ewf >= 0 && ewf <= 4){
		return compression_types[ewf];
	}
	fatal_rdd_error(RDD_BADARG, "unknown ewf compression argument %d\n", ewf);
	return "";
}

static unsigned
scan_uint(char *str)
{
	unsigned n;
	int rc;

	if ((rc = rdd_parse_uint((const char *) str, &n)) != RDD_OK) {
		fatal_rdd_error(rc, "%s", str);
	}
	return n;
}

static unsigned
scan_tcp_port(char *str)
{
	unsigned port;
	int rc;

	if ((rc = rdd_parse_tcp_port((const char *) str, &port)) != RDD_OK) {
		fatal_rdd_error(rc, "%s", str);
	}
	return port;
}

static void
init_options(void)
{
	memset(&opts, 0, sizeof opts);

	opts.mode = RDD_LOCAL;
	opts.server_port = DEFAULT_RDD_SERVER_PORT;
	opts.nretry = DEFAULT_NRETRY;
	opts.max_read_err = DEFAULT_MAX_READ_ERR;
	opts.blocklen = DEFAULT_BLOCK_LEN;
	opts.minblocklen = DEFAULT_MIN_BLOCK_SIZE;
	opts.histblocklen = DEFAULT_HIST_BLOCK_SIZE;
	opts.adler32len = DEFAULT_CHKSUM_BLOCK_SIZE;
	opts.crc32len = DEFAULT_CHKSUM_BLOCK_SIZE;
	opts.blockmd5len = DEFAULT_BLOCKMD5_SIZE;
	opts.output_count = 0;
	int i;
	for (i=0; i<RDD_MAX_OUTPUT_OPTS; i++) {
		opts.output[i].ewf = 0;
		opts.output[i].splitlen = 0;
		opts.output[i].outpath = 0;
		opts.output[i].server_host = 0;
		opts.output[i].server_port = DEFAULT_RDD_SERVER_PORT;
	}
}


/* Split host.dom.topdom:/tmp/d.img in host.dom.topdom and /tmp/d.img
 */
static void
split_host_file(const char *host_file, char **host, char **file)
{
	char *p;
	const char *h;
	const char *f;
	int hlen, flen;

	p = strchr(host_file, ':');
       	if (p == 0) {			/* no ':' in host_file */
		h = "localhost";
		hlen = strlen(h);
		f = host_file;
		flen = strlen(f);

	} else if (p == host_file) {	/* host_file starts with ':' */
		h = "localhost";
		hlen = strlen(h);
		f = p + 1;
		flen = strlen(f);
	} else {
		h = host_file;
		hlen = p - host_file;
		f = p + 1;
		flen = strlen(f);
	}
	if (flen == 0) {
		error("missing file name in target %s", host_file);
	}

	*host = rdd_malloc(hlen + 1);
	memcpy(*host, h, hlen);
	(*host)[hlen] = '\000';

	*file = rdd_malloc(flen + 1);
	memcpy(*file, f, flen);
	(*file)[flen] = '\000';
}

static void
process_options()
{
	char *arg;

	if (rdd_opt_set(opttab, "help")) {
		rdd_opt_usage(opttab, output_opttab, EXIT_SUCCESS);
	}

	if (rdd_opt_set(opttab, "version")) {
		fprintf(stdout, "%s version %s\n", PACKAGE, VERSION);
		exit(EXIT_SUCCESS);
	}

	opts.compress = rdd_opt_set(opttab, "compress");
	opts.quiet = rdd_opt_set(opttab, "quiet");
	rdd_set_quiet(opts.quiet);
#if !defined(HAVE_LIBZ)
	error("rdd not configured with compression support");
#endif

	opts.raw = rdd_opt_set(opttab, "raw");
#if !defined(__linux)
	if (opts.raw) {
		error("rdd raw-device support only works on Linux");
	}
#endif
	opts.inetd = rdd_opt_set(opttab, "inetd");
	opts.verbose = rdd_opt_set(opttab, "verbose");

	opts.raw = rdd_opt_set(opttab, "raw");
	if (opts.raw && opts.mode == RDD_SERVER) {
		error("raw-device input cannot be used in server mode");
	}

	opts.md5 = rdd_opt_set(opttab, "md5");
	opts.sha1 = rdd_opt_set(opttab, "sha1");
	opts.sha256 = rdd_opt_set(opttab, "sha256");
	opts.sha384 = rdd_opt_set(opttab, "sha384");
	opts.sha512 = rdd_opt_set(opttab, "sha512");
	
	opts.force_overwrite = rdd_opt_set(opttab, "force");
		
	if (rdd_opt_set_arg(opttab, "in", &arg)) {
		opts.infile = arg;
	} else {
		if (opts.mode != RDD_SERVER) {
			/* mandatory argument */
			rdd_opt_usage(opttab, output_opttab, EXIT_FAILURE);
		}
	}

	/* find the out option so we can retrieve the count */
	int i = 0;
	RDD_OPTION * output_option = 0;
	while (output_option == 0 && opttab[i].long_name != 0) {
		if (!strcmp(opttab[i].long_name, "--out")) {
			output_option = &opttab[i];
		}
		i++;
	}
	if (output_option == 0) {
		/* shouldn't happen! */
		error("internal error when looking for output option");
	}
	opts.output_count = output_option->count;
	
	for (i=0; i<opts.output_count; i++) {
		if(rdd_opt_set_arg(&all_output_opttabs[RDD_OUTPUT_OPTTAB_OPTION_COUNT * i], "ewf", &arg)){
			opts.output[i].ewf = check_compress_option(arg);
		}

		if (rdd_opt_set_arg(&all_output_opttabs[RDD_OUTPUT_OPTTAB_OPTION_COUNT * i], "split", &arg)) {
			opts.output[i].splitlen = scan_size(arg, 0);
		}
		if (rdd_opt_set_arg(&all_output_opttabs[RDD_OUTPUT_OPTTAB_OPTION_COUNT * i], "name", &arg)) {
			if (opts.mode == RDD_CLIENT) {
				split_host_file(arg,
					&opts.output[i].server_host,
					&opts.output[i].outpath);
			} else {
				opts.output[i].outpath = arg;
			}
		}
		if (opts.mode == RDD_CLIENT) {
			if (rdd_opt_set_arg(&all_output_opttabs[RDD_OUTPUT_OPTTAB_OPTION_COUNT * i], "port", &arg)) {
				opts.output[i].server_port = scan_tcp_port(arg);
			}
		}

	}

	if (rdd_opt_set_arg(opttab, "fault-simulation", &arg)) {
		opts.simfile = arg;
	}
	if (rdd_opt_set_arg(opttab, "log-file", &arg)) {
		opts.logfile = arg;
	}
	if (rdd_opt_set_arg(opttab, "adler32", &arg)) {
		opts.adler32file = arg;
	}
	if (rdd_opt_set_arg(opttab, "adler32-block-size", &arg)) {
		opts.adler32len= scan_size(arg, RDD_POSITIVE);
		if (opts.adler32file == 0) {
			error("missing Adler-32 output file name "
			      "(use --adler32)");
		}
	}
	if (rdd_opt_set_arg(opttab, "crc32", &arg)) {
		opts.crc32file = arg;
	}
	if (rdd_opt_set_arg(opttab, "crc32-block-size", &arg)) {
		opts.crc32len= scan_size(arg, RDD_POSITIVE);
		if (opts.crc32file == 0) {
			error("missing CRC-32 output file name "
			      "(use --crc32)");
		}
	}
	if (rdd_opt_set_arg(opttab, "histogram", &arg)) {
		opts.histfile = arg;
	}
	if (rdd_opt_set_arg(opttab, "histogram-block-size", &arg)) {
		opts.histblocklen = scan_size(arg, RDD_POSITIVE);
		if (opts.histfile == 0) {
			error("missing histogram output file name "
			      "(use --histogram)");
		}
	}
	if (rdd_opt_set_arg(opttab, "block-md5", &arg)) {
		opts.blockmd5file = arg;
	}
	if (rdd_opt_set_arg(opttab, "block-md5-size", &arg)) {
		opts.blockmd5len = scan_size(arg, RDD_POSITIVE);
		if (opts.blockmd5file == 0) {
			error("missing block-MD5 output file name "
			      "(use --block-md5)");
		}
	}
	if (rdd_opt_set_arg(opttab, "progress", &arg)) {
		opts.progresslen = scan_uint(arg);
	}
	if (rdd_opt_set_arg(opttab, "nretry", &arg)) {
		opts.nretry = scan_uint(arg);
	}
	if (rdd_opt_set_arg(opttab, "block-size", &arg)) {
		opts.blocklen = scan_size(arg, RDD_POSITIVE);
	}
	if (rdd_opt_set_arg(opttab, "min-block-size", &arg)) {
		opts.minblocklen = scan_size(arg, RDD_POSITIVE);
	}
	if (rdd_opt_set_arg(opttab, "offset", &arg)) {
		opts.offset = scan_size(arg, 0);
	}
	if (rdd_opt_set_arg(opttab, "count", &arg)) {
		opts.count = scan_size(arg, RDD_POSITIVE);
	}
	if (rdd_opt_set_arg(opttab, "max-read-err", &arg)) {
		opts.max_read_err = scan_uint(arg);
	}
	if (rdd_opt_set_arg(opttab, "port", &arg)) {
		if (opts.mode == RDD_SERVER) {
			opts.server_port = scan_tcp_port(arg);
		} else {
			error("can only specify general server port in server mode; use --out --port to specify port in client mode");
		}
	}
}

static void
command_line(int argc, char **argv)
{
	RDD_OPTION *od;
	unsigned i;
	char *opt;
	char *arg;

	/* Rdd operates in one of three modes (RDD_LOCAL, RDD_CLIENT, RDD_SERVER).
	 * The mode is determined by argv[1]: -C, -S, or something else.
	 */
	i = 1;
	opts.mode = RDD_LOCAL;
	if (argc > 1) {
		if (streq(argv[i], "-C") || streq(argv[i], "--client")) {
			opts.mode = RDD_CLIENT;
			i++;
		} else if (streq(argv[i], "-S") || streq(argv[i], "--server")) {
			opts.mode = RDD_SERVER;
			i++;
		}
	}

	/* Collect all other options and their arguments (if any).
	 */
	RDD_OPTION * current_tab = opttab;
	for (; i < (unsigned) argc; i++) {
		if ((od = rdd_get_opt_with_arg(current_tab, argv, argc, &i, &opt, &arg)) != 0) {
			/* Check whether the option is allowed in the current rdd mode.
			*/
			if (!flag_set(od->valid_modes, opts.mode)) {
				error("option %s not valid in %s mode", opt,
					opts.mode == RDD_LOCAL  ? "local" :
					opts.mode == RDD_CLIENT ? "client" :
					opts.mode == RDD_SERVER ? "server": "unknown");
			}
		}
		if (od == 0) {
			if (current_tab != opttab) {
				/* End of parse for output file; switch back to regular options and rescan this arg */
				current_tab = opttab;
				--i;
			} else {
				rdd_opt_usage(opttab, output_opttab, EXIT_FAILURE);
			}
		} else {

			if (!strcmp(od->long_name, "--out")) {
				if (od->count > RDD_MAX_OUTPUT_OPTS) {
					error("too many output files specified; maximum is %d", RDD_MAX_OUTPUT_OPTS);
				}
				/* Start of parse for output file;
				   copy the output_opttab table to the right position in the all_output_opttabs table */

				current_tab = all_output_opttabs + (od->count-1)*RDD_OUTPUT_OPTTAB_OPTION_COUNT;

				int j;
				for (j=0; j<RDD_OUTPUT_OPTTAB_OPTION_COUNT; j++) {
					current_tab[j] = output_opttab[j]; 
				}


			}
		}

	}

	process_options();

	if (argc - i != 0) {
		rdd_opt_usage(opttab, output_opttab, EXIT_FAILURE);
	}


	/* Artificial Intelligence
	 */
	if (rdd_opt_set(opttab, "block-size")
	&&  !rdd_opt_set(opttab, "min-block-size")
	&&  opts.blocklen < opts.minblocklen) {
		opts.minblocklen = opts.blocklen;
	}

	/* Sanity checks.
	 */
	if (opts.blocklen >= (rdd_count_t) INT_MAX) {
		error("block size (%llu) too large (larger than INT_MAX)",
			opts.blocklen);
	}
	if (opts.minblocklen > opts.blocklen) {
		error("minimum block length (%llu) cannot exceed "
		      "block length (%llu)",
			opts.minblocklen, opts.blocklen);
	}
	for (i=0; i<opts.output_count; i++) {
		if (opts.output[i].splitlen > 0 && opts.output[i].splitlen < opts.blocklen) {
			error("split size (%llu) must be larger than or "
		      	"equal to block size (%llu) in output #%d",
			opts.output[i].splitlen, opts.blocklen, i);
		}
		if (opts.output[i].splitlen > 0 && opts.output[i].outpath == 0) {
			error("--split requires an output file name in output #%d", i);
		}
		if (opts.output[i].splitlen != 0 && opts.output[i].splitlen < RDD_EWF_MIN_SPLITLEN && opts.output[i].ewf) {
			error("--ewf requires a split length of at least 1.0 MiB in output #%d", i);
		}
		if (compare_paths(opts.infile, opts.output[i].outpath) == 0) {
			error("input and output file cannot be the same (output #%d)", i);
		}
	}
}

static RDD_READER *
open_disk_input(rdd_count_t *inputlen)
{
	RDD_READER *reader = 0;
	int rc;

	rc = rdd_open_file_reader(&reader, opts.infile, opts.raw);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot open %s", opts.infile);
	}
	if ((rc = rdd_reader_seek(reader, 0)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot seek on %s", opts.infile);
	}

	if (opts.raw) {
		rc = rdd_open_aligned_reader(&reader, reader, RDD_SECTOR_SIZE);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot open %s for aligned access",
					opts.infile);
		}
	}

	*inputlen = RDD_WHOLE_FILE;
	if ((rc = rdd_device_size(opts.infile, inputlen)) != RDD_OK) {
		fatal_rdd_error(rc, "%s: cannot determine device size", opts.infile);
	}

	if (opts.simfile != 0) {
		rc = rdd_open_faulty_reader(&reader, reader, opts.simfile);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot initialize fault simulator");
		}
	}

	return reader;
}

static RDD_READER *
open_net_input(rdd_count_t *inputlen)
{
	RDD_READER *reader = 0;
	int server_sock = -1;
	unsigned flags;
	int fd = -1;
	int rc;

	*inputlen = RDD_WHOLE_FILE;

	/* In server mode, we read from the network */
	if (opts.inetd) {
		/* started by (x)inetd */
		fd = STDIN_FILENO;
	} else {
		rc = rdd_init_server(the_printer, opts.server_port,
				&server_sock);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot start rdd-copy server");
		}

		rc = rdd_await_connection(the_printer, server_sock, &fd);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "no connection");
		}
	}

	rc = rdd_open_fd_reader(&reader, fd);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot open reader on server socket");
	}
	
	/**
	 * For each output file, receive parameters. Do this until an empty file name is received.
	 */
	int compress = 0; /* compression will take place if at least one such flag has been received */
	rdd_output_opt_t current_output_opt;
	current_output_opt.outpath = "init"; /* to make while condition succeed the first time */
	rdd_count_t current_blocklen;	// blocklen may be transmitted multiple times but should be the same each time
	rdd_count_t current_inputlen;	// inputlen may be transmitted multiple times but should be the same each time
	while (current_output_opt.outpath[0] != '\0') {
		rc = rdd_recv_info(reader, &current_output_opt.outpath, &current_inputlen,
				&current_blocklen, &current_output_opt.splitlen, &current_output_opt.ewf, &flags);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "bad client request");
		}
		if (current_output_opt.outpath[0] != '\0') {
			if (opts.output_count + 1 >= RDD_MAX_OUTPUT_OPTS) {
				error("received too many output file requests");
			}
			opts.output[opts.output_count] = current_output_opt;
			opts.blocklen = current_blocklen;
			if ((flags & RDD_NET_COMPRESS) != 0) {
				compress = 1;
			}
			*inputlen = current_inputlen;
			++opts.output_count;
		}
	} 

	int i;
	if (opts.verbose) {
		logmsg("Received rdd request:");
		logmsg("\tfile size:   %s", rdd_strsize(*inputlen));
		logmsg("\tblock size:  %llu", opts.blocklen);
		for (i=0; i<opts.output_count; i++) {		
			logmsg("\toutput #%d:", i);
			logmsg("\tfile name:   %s", opts.output[i].outpath);
			logmsg("\tsplit size:  %llu", opts.output[i].splitlen);
			logmsg("\tewf compression: %s", print_ewf_compress_option());
		}
	}

	if (compress) {
		if ((rc = rdd_open_zlib_reader(&reader, reader)) != RDD_OK) {
			fatal_rdd_error(rc, "cannot open zlib reader");
		}
	}

	return reader;
}

/* Creates a reader stack that corresponds to the user's options.
 */
static RDD_READER *
open_input(rdd_count_t *inputlen)
{
	if (opts.mode == RDD_SERVER) {
		return open_net_input(inputlen);
	} else {
		return open_disk_input(inputlen);
	}
}

static RDD_WRITER *
open_disk_output(rdd_count_t outputsize, RDD_HASH_CONTAINER * hashcontainer, int output_number)
{
	RDD_WRITER *writer = 0;
	rdd_write_mode_t wrmode;
	int rc;

	rdd_output_opt_t * output_opts = &opts.output[output_number];

	if (output_opts->outpath == 0) {
		return 0;
	}

	wrmode = (opts.force_overwrite ? RDD_OVERWRITE_ASK : RDD_NO_OVERWRITE);

	if (strcmp(output_opts->outpath, "-") == 0) {
		if (output_opts->splitlen > 0) {
			error("cannot split standard output stream");
		}
		rc = rdd_open_fd_writer(&writer, STDOUT_FILENO);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot write to standard output?");
		}
	} else if (output_opts->ewf) {
		if (opts.sha256) {
			logmsg("Warning: cannot store SHA256 hash in ewf file");
		}
		if (opts.sha384) {
			logmsg("Warning: cannot store SHA384 hash in ewf file");
		}
		if (opts.sha512) {
			logmsg("Warning: cannot store SHA384 hash in ewf file");
		}
		rc = rdd_open_ewf_writer(&writer, output_opts->outpath, output_opts->splitlen, output_opts->ewf, wrmode, hashcontainer);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot open ewf output file %s",
					output_opts->outpath);
		}
	} else if (output_opts->splitlen > 0) {
		rc = rdd_open_part_writer(&writer, output_opts->outpath,
				outputsize, output_opts->splitlen, wrmode);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot open multipart output file");
		}
	} else {
		rc = rdd_open_safe_writer(&writer, output_opts->outpath, wrmode);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot open output file %s",
					output_opts->outpath);
		}
	}

	return writer;
}

static RDD_WRITER *
connection_exists(RDD_WRITER * writer_list[], int output_number, struct addrinfo * address)
{
	int i;
	int rc;
	int result;
	for (i=0; i<output_number; i++) {
		if (writer_list[i] != 0) { /* can be 0 if a net writer with the same address already existed */
			rc = rdd_compare_address(writer_list[i], address, &result);
			if (rc != RDD_OK) {
				fatal_rdd_error(rc, "cannot compare addresses");
			}
			if (result == 1) {
				return writer_list[i];
			}
		}
	}
	return 0;
}

static int
send_end_of_output_opts_marker(RDD_WRITER * tcp_writer_list[]) 
{
	int i;
	int rc;
	int result;
	for (i=0; i<opts.output_count; i++) {
		if (tcp_writer_list[i] != 0) { /* can be 0 if a net writer with the same address already existed */
			/* if this is a tcp writer, send empty file name to mark that no more output file options wil be sent */
			rc = rdd_compare_address(tcp_writer_list[i], 0, &result);
			if (rc != RDD_OK) {
				fatal_rdd_error(rc, "cannot compare addresses");
			}
			if (result == 0) {
				rc = rdd_send_info(tcp_writer_list[i], "\0", 0, 0, 0, 0, 0);	
				if (rc != RDD_OK) {
					return rc;
				}		
			}
		}		
	}
	return RDD_OK;
}

/**
 * \brief Open network output.
 * 
 * \param outputsize the size of the output
 * \param tcp_writer_list (in/out) the list of current tcp writers
 * \param num_tcp_writers (in/out) the size of the tcp_writer_list
 * \param output_number the index of the output parameter set on the command line
 *		for which we have to create a writer
 * \return the new writer
 * 
 * \note The tcp writer list is needed to be able to send an end-of-output-marker to
 * 		each writer. The actual writer returned by this function may be a
 * 		stacked writer (e.g. zlib), to which we cannot send the marker. We
 * 		also use the list to determine if a tcp writer with the same address *		already exists; in that case we just send meta-information.
 */
static RDD_WRITER *
open_net_output(rdd_count_t outputsize, RDD_WRITER * tcp_writer_list[], int * num_tcp_writers, int output_number)
{
	RDD_WRITER *writer = 0;
	unsigned flags = 0;
	int rc;
	char *server = opts.output[output_number].server_host;
	unsigned port = opts.output[output_number].server_port;
	int new_writer;

	assert(opts.output[output_number].outpath != 0);

	/**
	 * Find out if the connection has already been created by another writer.
	 */
	struct addrinfo * addr;
	rc = rdd_get_address(server, port, &addr);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "could not resolve server address");
	}

	if ((writer = connection_exists(tcp_writer_list, *num_tcp_writers, addr)) != 0) {
		/* send output parameters to existing writer */
		new_writer = 0;
	} else {
		rc = rdd_open_tcp_writer(&writer, server, port);

		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot connect to %s:%u", server, port);
		}
		tcp_writer_list[*num_tcp_writers] = writer;
		(*num_tcp_writers)++;
		new_writer = 1;
	}

	/**
	 * Send output parameters.
	 */
	flags = (opts.compress ? RDD_NET_COMPRESS : 0);

	rc = rdd_send_info(writer, opts.output[output_number].outpath, outputsize,
			opts.blocklen, opts.output[output_number].splitlen, opts.output[output_number].ewf, flags);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot send header to %s:%u", server, port);
	}


	if (new_writer) {
		if (opts.compress) {
			/* Stack a zlib writer on top of the TCP writer.
			*/
			rc = rdd_open_zlib_writer(&writer, writer);

			if (rc != RDD_OK) {
				fatal_rdd_error(rc, "cannot compress network traffic "
						"to %s:%u", server, port);
			}
		}
	}

	if (new_writer) {
		return writer;
	} else {
		return 0;
	}
}
/** Creates a writer stack that corresponds to the user's options.
 *  The outputsize argument contains the size of the output in
 *  bytes if that size is known or RDD_WHOLE_FILE if is not known.
 */
static RDD_WRITER *
open_output(rdd_count_t outputsize, RDD_HASH_CONTAINER * hashcontainer, RDD_WRITER * tcp_writer_list[], int * num_tcp_writers, int output_number)
{
	if (opts.mode == RDD_CLIENT) {
		return open_net_output(outputsize, tcp_writer_list, num_tcp_writers, output_number);
	} else {
		return open_disk_output(outputsize, hashcontainer, output_number);
	}
}

static void
open_logfile(void)
{
	RDD_MSGPRINTER *log_printer = 0;
	RDD_MSGPRINTER *bcast_printer = 0;
	RDD_MSGPRINTER *printers[2];
	unsigned nprinter = 0;
	int rc = RDD_OK;

	/* Keep the current (stderr) printer only if the user
	 * specified the verbose flag or if the user did not
	 * specify a log file.
	 */
	if (the_printer != 0 && (opts.verbose || opts.logfile == 0)) {
		printers[nprinter++] = the_printer;
	}

	/* If the user specified a log file then create a printer for
	 * it and add that printer to the printer list.
	 */
	if (opts.logfile != 0) {
		rc = rdd_mp_open_file_printer(&log_printer, opts.logfile, opts.force_overwrite);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot open log file (%s)",
					opts.logfile);
		}

		rc = rdd_mp_open_log_printer(&log_printer, log_printer);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot stack log printer");
		}

		printers[nprinter++] = log_printer;
	}

	/* Create a broadcast printer and make it the current printer.
	 */
	rc = rdd_mp_open_bcastprinter(&bcast_printer, nprinter, printers);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot open bcast printer");
	}
	the_printer = bcast_printer;
}

static void
close_printer(void)
{
	int rc;

	if (the_printer == 0) return;

	rc = rdd_mp_close(the_printer, RDD_MP_RECURSE|RDD_MP_READONLY);
	if (rc != RDD_OK) {
		/* Cannot trust the_printer any more...
		 */
		fprintf(stderr, "cannot close message printer\n");
		exit(EXIT_FAILURE);
	}

	the_printer = 0;
}



static void
log_header(char **argv, int argc)
{
	char cmdline[1024];
	char *p;
	int i;

	logmsg("");
	logmsg("%s", rdd_ctime());
	logmsg("%s version %s", PACKAGE, VERSION);
	logmsg("Copyright (c) 2002 Nederlands Forensisch Instituut");
#if defined(RDD_TRACE)
	logmsg("Compile-time flag RDD_TRACE is set");
#endif
#if defined(HAVE_LIBZ)
	logmsg("zlib version %s", zlibVersion());
	logmsg("Copyright (c) 1995-2002 Jean-loup Gailly and Mark Adler");
#endif
#ifdef HAVE_OPENSSL
	logmsg("openssl version %s", OPENSSL_VERSION_TEXT);
	logmsg("Copyright (c) 1995-1998 Eric Young");
#else
	logmsg("NOT using openssl");
#endif

	p = cmdline;
	snprintf(p, sizeof cmdline, "%s", argv[0]);
	cmdline[(sizeof cmdline) - 1] = '\000';
	p += strlen(argv[0]);
	for (i = 1; i < argc; i++) {
		snprintf(p, (sizeof cmdline) - (p - cmdline), " %s", argv[i]);
		cmdline[(sizeof cmdline) - 1] = '\000';
		p += 1 + strlen(argv[i]);
	}
	logmsg("%s", cmdline);
}

static void
log_params(rdd_copy_opts *opts)
{
	logmsg("========== Parameter settings ==========");
	logmsg("mode: %s",
		opts->mode == RDD_LOCAL ? "local" :
		opts->mode == RDD_CLIENT ? "client" :
		"server");
	logmsg("verbose: %s",                 bool2str(opts->verbose));
	logmsg("quiet: %s",                   bool2str(opts->quiet));
	logmsg("server port: %u",             opts->server_port);
	logmsg("input file: %s",              str2str(opts->infile));
	logmsg("log file: %s",                str2str(opts->logfile));
	int i;
	for (i=0; i<opts->output_count; i++) {
		logmsg("output #%d", 		      	i);
		logmsg("\toutput file: %s",             str2str(opts->output[i].outpath));
		logmsg("\tsegment size: %llu",          opts->output[i].splitlen);
		logmsg("\toutput as ewf compression: %s", print_ewf_compress_option());
		logmsg("\toutput host: %s",		opts->output[i].server_host);
		logmsg("\toutput port: %u",		opts->output[i].server_port);
	}
	logmsg("CRC32 file: %s",              str2str(opts->crc32file));
	logmsg("Adler32 file: %s",            str2str(opts->adler32file));
	logmsg("Statistics file: %s",         str2str(opts->histfile));
	logmsg("Block MD5 file: %s",          str2str(opts->blockmd5file));
	logmsg("raw-device input: %s",        bool2str(opts->raw));
	logmsg("compress network data: %s",   bool2str(opts->compress));
	logmsg("use (x)inetd: %s",            bool2str(opts->inetd));
	logmsg("force overwrite: %s",         bool2str(opts->force_overwrite));
	logmsg("compute MD5: %s",             bool2str(opts->md5));
	logmsg("compute SHA1: %s",            bool2str(opts->sha1));
	logmsg("compute SHA256: %s",          bool2str(opts->sha256));
	logmsg("compute SHA384: %s",          bool2str(opts->sha384));
	logmsg("compute SHA512: %s",          bool2str(opts->sha512));
	logmsg("max #retries: %u",            opts->nretry);
	logmsg("block size: %llu",            opts->blocklen);
	logmsg("minimum block size: %llu",    opts->minblocklen);
	logmsg("Adler32 block size: %llu",    opts->adler32len);
	logmsg("CRC32 block size: %llu",      opts->crc32len);
	logmsg("statistics block size: %llu", opts->histblocklen);
	logmsg("MD5 block size: %llu",        opts->blockmd5len);
	logmsg("input offset: %llu",          opts->offset);
	logmsg("input count: %llu",           opts->count);
	logmsg("progress reporting interval: %llu", opts->progresslen);
	logmsg("max #errors to tolerate: %llu",     opts->max_read_err);
	logmsg("========================================");
	logmsg("");
}

static void
handle_read_error(rdd_count_t offset, unsigned nbyte, void *env)
{
	logmsg("read error: offset %llu bytes, count %u bytes",
		offset, nbyte);
}

static void
handle_substitution(rdd_count_t offset, unsigned nbyte, void *env)
{
	logmsg("input dropped: offset %llu bytes, count %u bytes",
		offset, nbyte);
}

static int
handle_progress(rdd_count_t pos, rdd_count_t nsubst, void *env)
{
	RDD_PROGRESS *p = (RDD_PROGRESS *) env;
	RDD_PROGRESS_INFO info;
	double megabytes_per_sec;
	double gigabytes_done;
	double perc_done;
	double secs_left;

	int rc;

	if ((rc = rdd_progress_update(p, pos, nsubst)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot update progress object");
	}

	rc = rdd_progress_poll(p, &info);
	if (rc == RDD_EAGAIN) {
		return RDD_OK;
	} else if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot obtain progress information");
	}

	/* The poll succeeded.  Print progress information.
	 */
	gigabytes_done = (double) info.pos / (double) (1 << 30);
	megabytes_per_sec = info.speed / (double) (1 << 20);

	if (info.fraction >= 0.0) {
		/* If we know the input size, we can give a more
		 * detailed progress report.
		 */
		perc_done = 100.0 * info.fraction;
		if (info.speed == 0) {
			secs_left = 0;
		} else {
			secs_left = ((double)(p->input_size - pos)) / info.speed;
		}

		int days, hours, mins, secs;
		rc = timeUnits(secs_left, &secs, &mins, &hours, &days);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot compute time units");
		}

		fprintf(stderr, 
			"Estimated time remaining: %d day(s) %d hour(s) %d minute(s) %d second(s)\n",
			days, hours, mins, secs);

		fprintf(stderr, "%.3f GB done (%6.2f%%), "
			"average speed %.3f MB/s"
			" (%.0f seconds remaining)"
			", substituted %lu bytes "
			"\n", 
			gigabytes_done, perc_done, megabytes_per_sec
			, secs_left
			, (long unsigned int) info.nsubst
			);
	} else {
		/* Unknown input size, so we cannot make any
		 * predictions.
		 */
		fprintf(stderr, "%.3f GB done, average speed %.3f MB/s, subsituted %lu bytes\n", 
			gigabytes_done, megabytes_per_sec, (long unsigned int) info.nsubst);
	}

	return RDD_OK;
}

static void
add_filter(RDD_FILTERSET *fset, const char *name, RDD_FILTER *f)
{
	int rc;

	if ((rc = rdd_fset_add(fset, name, f)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot install %s filter", name);
	}
}

static void
install_filters(RDD_FILTERSET *fset, RDD_WRITER * writers[])
{
	RDD_FILTER *f = 0;
	int rc;
	char writer_name[16];

	if ((rc = rdd_fset_init(fset)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot create filter fset");
	}

	int i;
	for (i=0; i<opts.output_count; i++) {
		if (writers[i] != 0) { // writers[i[ can be 0 if there was another net writer to the same host
			rc = rdd_new_write_streamfilter(&f, writers[i]);
			if (rc != RDD_OK) {
				fatal_rdd_error(rc, "cannot create write filter");
			}
			if (snprintf(writer_name, sizeof(writer_name), "writer_%d", i) >= sizeof(writer_name)) {
				/* shouldn't happen! */
				error("writer name too long");
			}	
			add_filter(fset, writer_name, f);
		}
	}

	if (opts.md5) {
		rc = rdd_new_md5_streamfilter(&f);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create MD5 filter");
		}
		add_filter(fset, "MD5 stream", f);
	}

	if (opts.sha1) {
		rc = rdd_new_sha1_streamfilter(&f);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create SHA-1 filter");
		}
		add_filter(fset, "SHA-1 stream", f);
	}
	
	if (opts.sha256) {
		rc = rdd_new_sha256_streamfilter(&f);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create SHA-256 filter");
		}
		add_filter(fset, "SHA-256 stream", f);
	}
	
	if (opts.sha384) {
		rc = rdd_new_sha384_streamfilter(&f);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create SHA-384 filter");
		}
		add_filter(fset, "SHA-384 stream", f);
	}
	
	if (opts.sha512) {
		rc = rdd_new_sha512_streamfilter(&f);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create SHA-512 filter");
		}
		add_filter(fset, "SHA-512 stream", f);
	}

	if (opts.blockmd5file != 0) {
		rc = rdd_new_md5_blockfilter(&f, opts.blockmd5len,
						opts.blockmd5file,
						opts.force_overwrite);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create MD5 block filter");
		}
		add_filter(fset, "MD5 block", f);
	}

	if (opts.histfile != 0) {
		rc = rdd_new_stats_blockfilter(&f,
				opts.histblocklen, opts.histfile,
				opts.force_overwrite);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create statistics filter");
		}
		add_filter(fset, "statistical block", f);
	}

	if (opts.adler32file != 0) {
		rc = rdd_new_adler32_blockfilter(&f,
				opts.adler32len, opts.adler32file,
				opts.force_overwrite);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create Adler32 filter");
		}
		add_filter(fset, "Adler32 block", f);
	}

	if (opts.crc32file != 0) {
		rc = rdd_new_crc32_blockfilter(&f,
				opts.crc32len, opts.crc32file,
				opts.force_overwrite);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create CRC-32 filter");
		}
		add_filter(fset, "CRC-32 block", f);
	}
}

static RDD_COPIER *
create_copier(rdd_count_t input_size, RDD_PROGRESS *progress)
{
	RDD_COPIER *copier = 0;
	rdd_count_t count = 0;
	int rc;

	/* Process the offset option.
	 */
	if (opts.offset > input_size) {
		error("offset %llu larger than input file size (%s)",
			opts.offset, rdd_strsize(input_size));
	}

	/* Process the count option.
	 */
	if (input_size == RDD_WHOLE_FILE) {
		count = RDD_WHOLE_FILE;
	} else {
		count = input_size - opts.offset;
	}
	if (opts.count > 0) {
	       	if (opts.count <= count) {
			count = opts.count; /* Use user-specified count */
		} else {
			logmsg("User count (%llu) too large; ignored", opts.count);
		}
	}
	if (opts.verbose) {
		logmsg("input size: %s", rdd_strsize(input_size));
		logmsg("read size: %s", rdd_strsize(count));
	}


	if (opts.mode == RDD_SERVER) {
		RDD_SIMPLE_PARAMS p;

		memset(&p, 0, sizeof p);
		if (progress != 0) {
			p.progressfun = handle_progress;
			p.progressenv = progress;
		}

		rc = rdd_new_simple_copier(&copier, &p);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create simple copier");
		}
	} else {
		RDD_ROBUST_PARAMS p;

		memset(&p, 0, sizeof p);
		p.minblocklen = opts.minblocklen;
		p.maxblocklen = opts.blocklen;
		p.nretry = opts.nretry;
		p.maxsubst = opts.max_read_err;
		p.readerrfun = handle_read_error;
		p.substfun = handle_substitution;
		if (progress != 0) {
			p.progressfun = handle_progress;
			p.progressenv = progress;
		}

		rc = rdd_new_robust_copier(&copier,
				opts.offset, count, &p);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot create robust copier");
		}
	}

	return copier;
}

static void
process_hash_result(RDD_FILTERSET *fset, const char *hash_name,
		const char *filter_name, unsigned mdsize, RDD_HASH_CONTAINER * hashcontainer)
{
	unsigned char md[RDD_MAX_DIGEST_LENGTH];
	char hexdigest[2*RDD_MAX_DIGEST_LENGTH + 1];
	RDD_FILTER *f = 0;
	int rc;

	memset(md, 0, mdsize);

	if (mdsize > (sizeof md)) {
		fatal_rdd_error(RDD_ESPACE, "digest size exceeds buffer size");
	}

	if ((rc = rdd_fset_get(fset, filter_name, &f)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot find %s filter", filter_name);
	}

	if ((rc = rdd_filter_get_result(f, md, mdsize)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot get result for %s filter",
				filter_name);
	}


	rc = rdd_buf2hex(md, mdsize, hexdigest, sizeof hexdigest);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "cannot convert binary digest");
	}

	/* Store hash for processing by writers */
	if ((rc = rdd_set_hash(hashcontainer, hash_name, md)) != RDD_OK) {
		fatal_rdd_error(rc, "error storing hash %s", hash_name);
	}


	logmsg("%s: %s", hash_name, hexdigest);
}

int
main(int argc, char **argv)
{
	double start, end;
	RDD_READER *reader;
	RDD_WRITER * writers[RDD_MAX_OUTPUT_OPTS];
	RDD_WRITER * tcp_writers[RDD_MAX_OUTPUT_OPTS];
	int num_tcp_writers = 0;
	RDD_PROGRESS progress;
	RDD_COPIER_RETURN copier_ret;
	RDD_COPIER *copier;
	RDD_FILTERSET filterset;
	RDD_MSGPRINTER *printer = 0;
	RDD_HASH_CONTAINER *hashcontainer = 0;
	rdd_count_t input_size;
	int rc;
	int i;

	/* Initialise writers array.
	 */
	for (i=0; i<RDD_MAX_OUTPUT_OPTS; i++) {
		writers[i] = 0;
		tcp_writers[i] = 0;
	}

	set_progname(argv[0]);
	rdd_cons_open();
	rdd_init();
	/* Setup initial printer (stderr).
	 */
	rc = rdd_mp_open_stdio_printer(&printer, stderr);
	if (rc != RDD_OK) {
		fprintf(stderr, "cannot open stderr message printer\n");
		exit(EXIT_FAILURE);
	}
#if 0
	rc = rdd_mp_open_log_printer(&printer, printer);
	if (rc != RDD_OK) {
		exit(EXIT_FAILURE);
	}
#endif
	the_printer = printer;

	init_options();
	rdd_opt_init(usage_message);
	command_line(argc, argv);
	open_logfile();

	rdd_catch_signals();

	log_header(argv, argc);
	log_params(&opts);

	if (!opts.md5 && !opts.sha1 && !opts.sha256 && !opts.sha384 && !opts.sha512) {
	       rdd_quit_if(RDD_NO, "Continue without hashing (yes/no)?");
	}
	if (opts.logfile == 0) {
		rdd_quit_if(RDD_NO, "Continue without logging (yes/no)?");
	}

	reader = open_input(&input_size);

	if ((rc = rdd_new_hashcontainer(&hashcontainer)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot create hashes object");	
	}

	for (i=0; i<opts.output_count; i++) {
		writers[i] = open_output(RDD_WHOLE_FILE, hashcontainer, tcp_writers, &num_tcp_writers, i);
	}
	/* Let all tcp writers send an end-of-meta-information marker. Note that the top-level writers (which may be e.g. zlib writers stacked on tcp writers) cannot send these since the meta-information contains flags about e.g. compression. */
	if ((rc = send_end_of_output_opts_marker(tcp_writers)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot send end of output opts marker");
	}

	install_filters(&filterset, writers);

	if (opts.progresslen > 0) {
		rc = rdd_progress_init(&progress, input_size, opts.progresslen);
		if (rc != RDD_OK) {
			fatal_rdd_error(rc, "cannot initialize progress object");
		}
		copier = create_copier(input_size, &progress);
	} else {
		copier = create_copier(input_size, 0);
	}

	start = rdd_gettime();
	rc = rdd_copy_exec(copier, reader, &filterset, &copier_ret);
	if (rc != RDD_OK) {
		fatal_rdd_error(rc, "copy failed");
	}
	end = rdd_gettime();

	rdd_mp_message(the_printer, RDD_MSG_INFO, "=== done ***");
	rdd_mp_message(the_printer, RDD_MSG_INFO, "seconds: %.3f", end - start);
	rdd_mp_message(the_printer, RDD_MSG_INFO, "bytes written: %llu", 
						  copier_ret.nbyte);
	rdd_mp_message(the_printer, RDD_MSG_INFO, "bytes lost: %llu", 
						  copier_ret.nlost);
	rdd_mp_message(the_printer, RDD_MSG_INFO, "read errors: %lu", 
						  copier_ret.nread_err);
	rdd_mp_message(the_printer, RDD_MSG_INFO, "zero-block substitutions: "
						  "%lu", copier_ret.nsubst);

	if (opts.md5) {
		process_hash_result(&filterset, RDD_MD5, "MD5 stream", MD5_DIGEST_LENGTH, hashcontainer);
	} else {
		logmsg("MD5: <none>");
	}
	if (opts.sha1) {
		process_hash_result(&filterset, RDD_SHA1, "SHA-1 stream", SHA_DIGEST_LENGTH, hashcontainer);
	} else {
		logmsg("SHA1: <none>");
	}
	if (opts.sha256) {
		process_hash_result(&filterset, RDD_SHA256, "SHA-256 stream", SHA256_DIGEST_LENGTH, hashcontainer);
	} else {
		logmsg("SHA256: <none>");
	}
	if (opts.sha384) {
		process_hash_result(&filterset, RDD_SHA384, "SHA-384 stream", SHA384_DIGEST_LENGTH, hashcontainer);
	} else {
		logmsg("SHA384: <none>");
	}
	if (opts.sha512) {
		process_hash_result(&filterset, RDD_SHA512, "SHA-512 stream", SHA512_DIGEST_LENGTH, hashcontainer);
	} else {
		logmsg("SHA512: <none>");
	}

	if ((rc = rdd_copy_free(copier)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot clean up copier");
	}

	for (i=0; i<opts.output_count; i++) {
		if (writers[i] != 0) {
			if ((rc = rdd_writer_close(writers[i])) != RDD_OK) {
				fatal_rdd_error(rc, "cannot clean up writer");
			}
		}
	}

	if ((rc = rdd_fset_clear(&filterset)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot clean up filters");
	}

	if ((rc = rdd_reader_close(reader, 1)) != RDD_OK) {
		fatal_rdd_error(rc, "cannot clean up reader");
	}

	close_printer();

	if (copier_ret.nread_err > 0) {
		logmsg("%u read errors occurred", copier_ret.nread_err);
		exit(EXIT_FAILURE);
	}

	logmsg("no read errors");


	rdd_cons_close();

	return 0;
}
