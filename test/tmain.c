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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "testhelper.h"

#define WAIT_TIME 1

static int isReadOnly(char * filename, int * readOnly)
{
	CHECK_NOT_NULL(readOnly);
	struct stat buf;
	CHECK_INT(0, stat(filename, &buf));
	mode_t mode = buf.st_mode;
	int writable = ((mode & S_IWUSR) || (mode & S_IWGRP) || (mode & S_IWOTH));
	*readOnly = !writable;
	return 1;
}

/* Stop processes in case some are still running -- which is an error */
static int 
stop_processes(int report)
{
	char kill_cmd[] = "killall lt-rdd-copy ";
	if (report) {
		CHECK_EXITSTATUS(EXIT_FAILURE, system(kill_cmd)); // no processes should be killed, so this should result in a faillure
		
	} else {
		IGNORE_RESULT(system(kill_cmd));
	}
	return 1;
}

/**
 * Most tests are run with -q to prevent needing extra input.
 */
static int test_unknown_command()
{
	CHECK_EXITSTATUS(EXIT_FAILURE, system(COMMANDLINE("-q -unknown in out")));
	return 1;
} 

static int test_help_short()
{
	CHECK_EXITSTATUS(EXIT_SUCCESS, system(COMMANDLINE("-?")));
	return 1;
} 

static int test_help_long()
{
	CHECK_EXITSTATUS(EXIT_SUCCESS, system(COMMANDLINE("--help")));
	return 1;
} 

/*
 * Regression test for bug RDD-217.
 */
static int test_empty_input()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in /dev/null --out --name simpletestoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp /dev/null simpletestoutput"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f simpletestoutput"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f simpletestoutput"));
	return 0;
}

static int test_quiet_short()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in simpletestfile.txt --out --name simpletestoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt simpletestoutput"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f simpletestoutput"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f simpletestoutput"));
	return 0;
}

static int test_quiet_long()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("--quiet --in simpletestfile.txt --out --name simpletestoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt simpletestoutput"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f simpletestoutput"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f simpletestoutput"));
	return 0;
}

static int test_sha1()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --sha1 --in simpletestfile.txt --out --name simpletestoutput")));

	// todo: test hash value?

	int readOnly = 0;
	CHECK_INT(1, isReadOnly("simpletestoutput", &readOnly));
	CHECK_INT(1, readOnly);


	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt simpletestoutput"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f simpletestoutput"));
	return 1;

error:
	IGNORE_RESULT(system("rm -f simpletestoutput"));
	return 0;
}

static int test_ewf_short()
{

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out -e none --name testoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput.E01 > checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	int readOnly = 0;
	CHECK_INT(1, isReadOnly("testoutput.E01", &readOnly));
	CHECK_INT(1, readOnly);

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput.E01"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));


	return 1;
error:
	IGNORE_RESULT(system("rm -f testoutput.E01"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}

static int test_ewf_long()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out --ewf fast --name testoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput.E01 > checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput.E01"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f testoutput.E01"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}

static int test_ewf_compression_none()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out --ewf none --name testoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput.E01 > checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput.E01"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f testoutput.E01"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}

static int test_ewf_compression_best()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out --ewf best --name testoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput.E01 > checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput.E01"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f testoutput.E01"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}

static int test_ewf_compression_fast()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out --ewf fast --name testoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput.E01 > checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput.E01"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f testoutput.E01"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}

static int test_ewf_compression_empty_block()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out --ewf empty-block --name testoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput.E01 > checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput.E01"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f testoutput.E01"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}

static int test_split_local()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out --name testoutput -s 6000000")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cat 000000-testoutput 000001-testoutput > checkfile"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000000-testoutput"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000001-testoutput"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f 000000-testoutput"));
	IGNORE_RESULT(system("rm -f 000001-testoutput"));
	IGNORE_RESULT(system("rm -f checkfile"));

	return 0;
}

static int test_split_local_ewf()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out -s 2000000 -e best --name testoutput")));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput.E01 > checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput.E01"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput.E02"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));
	
	return 1;

error:
	IGNORE_RESULT(system("rm -f testoutput.E01"));
	IGNORE_RESULT(system("rm -f testoutput.E02"));
	IGNORE_RESULT(system("rm -f checkfile"));

	return 0;
}

static int test_split_toosmall()
{
	CHECK_EXITSTATUS(EXIT_FAILURE, system(COMMANDLINE("-q --in simpletestfile.txt --out -s 1000 --name simpletestoutput")));
	return 1;

}

static int test_multiple_output_local()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in simpletestfile.txt --out --name testoutput1 --out --name testoutput2 --out --name testoutput3 --out --name testoutput4")));	

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput3"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput4"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput3"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput4"));
	return 1;

error:
	IGNORE_RESULT(system("rm -f testoutput1"));
	IGNORE_RESULT(system("rm -f testoutput2"));
	IGNORE_RESULT(system("rm -f testoutput3"));
	IGNORE_RESULT(system("rm -f testoutput4"));
	return 0;
}

static int test_multiple_output_local_partly_ewf()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out --name testoutput1 --out -e empty-block --name testoutput2 --out --name testoutput3 -e best --out --name testoutput4")));	

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd testoutput1"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput2.E01 > checkfile"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput3.E01 > checkfile"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd testoutput4"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput2.E01"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput3.E01"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput4"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));
	return 1;

error:
	IGNORE_RESULT(system("rm -f testoutput1"));
	IGNORE_RESULT(system("rm -f testoutput2.E01"));
	IGNORE_RESULT(system("rm -f testoutput3.E01"));
	IGNORE_RESULT(system("rm -f testoutput4"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}

static int test_multiple_output_local_partly_split()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out -s 6000000 --name testoutput1 --out -s 4000000 --name testoutput2 --out --name testoutput3 --out --name testoutput4")));	


	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cat 000000-testoutput1 000001-testoutput1 > checkfile"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));



	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cat 000000-testoutput2 000001-testoutput2 000002-testoutput2 > checkfile"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));


	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd testoutput3"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd testoutput4"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000000-testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000001-testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000000-testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000001-testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000002-testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput3"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput4"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));
	return 1;

error:
	IGNORE_RESULT(system("rm -f 000000-testoutput1"));
	IGNORE_RESULT(system("rm -f 000001-testoutput1"));
	IGNORE_RESULT(system("rm -f 000000-testoutput2"));
	IGNORE_RESULT(system("rm -f 000001-testoutput2"));
	IGNORE_RESULT(system("rm -f 000002-testoutput2"));
	IGNORE_RESULT(system("rm -f testoutput3"));
	IGNORE_RESULT(system("rm -f testoutput4"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}

static int test_multiple_output_local_split_ewf()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-q --in 8-jpeg-search.dd --out -s 6000000 --name testoutput1 --out -s 2000000 -e none --name testoutput2 --out -e fast --name testoutput3 --out --name testoutput4")));


	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cat 000000-testoutput1 000001-testoutput1 > checkfile"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput2.E01 > checkfile"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput3.E01 > checkfile"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd testoutput4"));


	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000000-testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000001-testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000000-testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput2.E01"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput2.E02"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput3.E01"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput4"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));

	return 1;

error:
	IGNORE_RESULT(system("rm -f 000000-testoutput1"));
	IGNORE_RESULT(system("rm -f 000001-testoutput1"));
	IGNORE_RESULT(system("rm -f testoutput2.E01"));
	IGNORE_RESULT(system("rm -f testoutput2.E02"));
	IGNORE_RESULT(system("rm -f testoutput3.E01"));
	IGNORE_RESULT(system("rm -f testoutput4"));
	IGNORE_RESULT(system("rm -f checkfile"));

	return 0;
}

static int
test_server_output_file()
{
	CHECK_EXITSTATUS(EXIT_FAILURE, system(COMMANDLINE("-S --out --name testoutput")));
	return 1;
}

static int
test_server_input_file()
{
	CHECK_EXITSTATUS(EXIT_FAILURE, system(COMMANDLINE("-S --in simpletestfile.txt")));
	return 1;
}


static int
test_client_server()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q")));
	/* wait a bit until the server has started */
	sleep(WAIT_TIME);

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-C -q --in simpletestfile.txt --out --name localhost:testoutput")));
	/* wait a bit until the server has finished */
	sleep(WAIT_TIME);

	CHECK_INT_GOTO(1, stop_processes(1));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput"));
	return 1;
error:
	IGNORE_RESULT(stop_processes(0));
	IGNORE_RESULT(system("rm -f testoutput"));

	return 0;
}

static int
test_client_server_multiple_output()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q")));
	/* wait a bit until the server has started */
	sleep(WAIT_TIME);

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-C -q --in simpletestfile.txt --out --name localhost:testoutput1 --out --name localhost:testoutput2 --out --name localhost:testoutput3 --out --name localhost:testoutput4")));
	/* wait a bit until the server has finished */
	sleep(WAIT_TIME);

	CHECK_INT_GOTO(1, stop_processes(1));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput3"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput4"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput3"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput4"));
	return 1;

error:
	IGNORE_RESULT(stop_processes(0));
	IGNORE_RESULT(system("rm -f testoutput1"));
	IGNORE_RESULT(system("rm -f testoutput2"));
	IGNORE_RESULT(system("rm -f testoutput3"));
	IGNORE_RESULT(system("rm -f testoutput4"));
	return 0;
}

static int
test_client_server_with_port()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q -p 8000")));
	/* wait a bit until the server has started */
	sleep(WAIT_TIME);

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-C -q --in simpletestfile.txt --out --name localhost:testoutput --port 8000")));
	/* wait a bit until the server has finished */
	sleep(WAIT_TIME);

	CHECK_INT_GOTO(1, stop_processes(1));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput"));
	return 1;
error:
	IGNORE_RESULT(stop_processes(0));
	IGNORE_RESULT(system("rm -f testoutput"));

	return 0;
}

static int
test_client_two_servers_with_different_port()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q -p 8000")));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q -p 9000")));
	/* wait a bit until the servers have started */
	sleep(WAIT_TIME);

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-C -q --in simpletestfile.txt --out --name localhost:testoutput1 --port 8000 --out --name localhost:testoutput2 --port 9000")));

	/* wait a bit until the server has finished */
	sleep(WAIT_TIME);

	CHECK_INT_GOTO(1, stop_processes(1));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput2"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput2"));
	return 1;
error:
	IGNORE_RESULT(stop_processes(0));
	IGNORE_RESULT(system("rm -f testoutput1"));
	IGNORE_RESULT(system("rm -f testoutput2"));

	return 0;
}

static int
test_client_two_servers_with_three_files()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q -p 8000")));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q -p 9000")));
	/* wait a bit until the servers have started */
	sleep(WAIT_TIME);

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-C -q --in simpletestfile.txt --out --name localhost:testoutput1 --port 8000 --out --name localhost:testoutput2 --port 9000 --out --name localhost:testoutput3 --port 9000")));

	/* wait a bit until the server has finished */
	sleep(WAIT_TIME);

	CHECK_INT_GOTO(1, stop_processes(1));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput3"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput1"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput2"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput3"));
	return 1;
error:
	IGNORE_RESULT(stop_processes(0));
	IGNORE_RESULT(system("rm -f testoutput1"));
	IGNORE_RESULT(system("rm -f testoutput2"));
	IGNORE_RESULT(system("rm -f testoutput3"));
	return 0;
}

static int
test_client_server_with_ewf()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q")));
	/* wait a bit until the server has started */
	sleep(WAIT_TIME);

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-C -q --in 8-jpeg-search.dd --out --name localhost:testoutput --ewf none")));

	/* wait a bit until the server has finished */
	sleep(WAIT_TIME);

	CHECK_INT_GOTO(1, stop_processes(1));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("tools/rfile-cat testoutput.E01 > checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput.E01"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));


	return 1;
error:
	IGNORE_RESULT(stop_processes(0));
	IGNORE_RESULT(system("rm -f testoutput.E01"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}

static int
test_client_server_with_split()
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q")));
	/* wait a bit until the server has started */
	sleep(WAIT_TIME);

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-C -q --in 8-jpeg-search.dd --out --name testoutput -s 6000000")));
	sleep(WAIT_TIME);

	/* wait a bit until the server has finished */
	sleep(WAIT_TIME);

	CHECK_INT_GOTO(1, stop_processes(1));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cat 000000-testoutput 000001-testoutput > checkfile"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp 8-jpeg-search.dd checkfile"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000000-testoutput"));
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f 000001-testoutput"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f checkfile"));


	return 1;
error:
	IGNORE_RESULT(stop_processes(0));
	IGNORE_RESULT(system("rm -f 000000-testoutput"));
	IGNORE_RESULT(system("rm -f 000001-testoutput"));
	IGNORE_RESULT(system("rm -f checkfile"));
	return 0;
}



static int
test_client_server_with_compression() // regression test for bug #3341
{
	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE_BG("-S -q")));
	sleep(WAIT_TIME);

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system(COMMANDLINE("-C -q -z --in simpletestfile.txt --out --name localhost:testoutput")));
	/* wait a bit until the server has finished */
	sleep(WAIT_TIME);

	CHECK_INT_GOTO(1, stop_processes(1));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("cmp simpletestfile.txt testoutput"));

	CHECK_EXITSTATUS_GOTO(EXIT_SUCCESS, system("rm -f testoutput"));

	return 1;
error:
	IGNORE_RESULT(stop_processes(0));
	IGNORE_RESULT(system("rm -f testoutput"));

	return 0;

}


static int
call_tests(void)
{
	int result = 1;

	TEST(test_unknown_command);
	TEST(test_help_short);
	TEST(test_help_long);
    TEST(test_empty_input);
	TEST(test_quiet_short);
	TEST(test_quiet_long);
	TEST(test_sha1);
	TEST(test_ewf_short);
	TEST(test_ewf_long);
	TEST(test_ewf_compression_none);
	TEST(test_ewf_compression_best);
	TEST(test_ewf_compression_fast);
	TEST(test_ewf_compression_empty_block);
	TEST(test_split_local);
	TEST(test_split_local_ewf);
	TEST(test_split_toosmall);
	TEST(test_multiple_output_local);
	TEST(test_multiple_output_local_partly_ewf);
	TEST(test_multiple_output_local_partly_split);
	TEST(test_multiple_output_local_split_ewf);
	TEST(test_server_output_file);
	TEST(test_server_input_file);

	TEST(test_client_server);
	TEST(test_client_server_multiple_output);
	TEST(test_client_server_with_port);
	TEST(test_client_two_servers_with_different_port);
	TEST(test_client_two_servers_with_three_files);
	TEST(test_client_server_with_ewf);
	TEST(test_client_server_with_split);
	TEST(test_client_server_with_compression);

	return result;
}

TEST_MAIN;
