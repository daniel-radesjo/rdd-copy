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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>



#include "rdd.h"
#include "commandline.c"

#include "testhelper.h"

static int 
test_opt_init_null()
{
	rdd_opt_init(0);
	return 1;
}

static int 
test_opt_init()
{
	rdd_opt_init("some text");
	return 1;
}

static int
test_match_name_input_null()
{
	CHECK_INT(0, match_name(0, "short", "loooooooong"));
	return 1;
}

static int
test_match_name_short_name_null_false()
{
	CHECK_INT(0, match_name("input", 0, "loooooooong"));
	return 1;
}

static int
test_match_name_short_name_null_true()
{
	CHECK_INT(1, match_name("loooooooong", 0, "loooooooong"));
	return 1;
}

static int
test_match_name_long_name_null_false()
{
	CHECK_INT(0, match_name("input", "short", 0));
	return 1;
}

static int
test_match_name_long_name_null_true()
{
	CHECK_INT(1, match_name("short", "short", 0));
	return 1;
}

static int
test_match_name_false()
{
	CHECK_INT(0, match_name("input", "short", "looooooong"));
	return 1;
}

static int
test_match_name_match_short()
{
	CHECK_INT(1, match_name("input", "input", "looooooong"));
	return 1;
}

static int
test_match_name_match_long()
{
	CHECK_INT(1, match_name("input", "short", "input"));
	return 1;
}

static int
test_match_name_case()
{
	CHECK_INT(0, match_name("Input", "input", "INPUT"));
	return 1;
}

static int
test_match_name_same_short_long()
{
	CHECK_INT(0, match_name("Input", "short", "short"));
	return 1;
}

static int
test_get_opt_with_arg_tab_null()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	char * argv[] = {"yyy", "zzz", "-x1"};

	i = 2;
	option = rdd_get_opt_with_arg(0, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_UINT(2, i);
	return 1;
}

static int
test_get_opt_with_arg_argv_null()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
        {0,	0,		0,	0,			0,	0,	0} /* sentinel */
	};

	i = 2;
	option = rdd_get_opt_with_arg(opttab, 0, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_UINT(2, i);
	return 1;
}

static int
test_get_opt_with_arg_argc_nonpositive()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
        {0,	0,		0,	0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "-x1"};

	i = 2;
	option = rdd_get_opt_with_arg(opttab, argv, -1, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_UINT(2, i);
	return 1;
}

static int
test_get_opt_with_arg_i_null()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;

	RDD_OPTION opttab[] = {
        {0,	0,		0,	0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "-x1"};

	option = rdd_get_opt_with_arg(opttab, argv, 3, 0, &optname, &arg);
	CHECK_NULL(option);
	return 1;
}

static int
test_get_opt_with_arg_i_too_large()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
        {0,	0,		0,	0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "-x1"};

	i = 3;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_UINT(3, i);
	return 1;
}

static int
test_get_opt_with_arg_i_negative()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
        {0,	0,		0,	0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "-x1"};

	i = -1;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_UINT(-1, i);
	return 1;
}

static int
test_get_opt_with_arg_opt_null()
{
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
        {0,	0,		0,	0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "-x1"};

	i = 2;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, 0, &arg);
	CHECK_NULL(option);
	CHECK_UINT(2, i);
	return 1;
}

static int
test_get_opt_with_arg_arg_null()
{
	char * optname;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
        {0,	0,		0,	0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "-x1"};

	i = 2;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, 0);
	CHECK_NULL(option);
	CHECK_UINT(2, i);
	return 1;
}

static int
test_get_opt_with_arg_found_short()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 	0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	0, 	0, 	"X2!",	0,	0},
	{"-x3",	"--xxx3", 	0, 	0, 	"X3!",	0,	0},
        {0,	0,		0,	0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "-x1"};

	i = 0;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(0, i);
	

	i = 1;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(1, i);

	i = 2;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NOT_NULL(option);
	CHECK_STRING("-x1", option->short_name);
	CHECK_STRING("-x1", optname);
	CHECK_NULL(arg);
	CHECK_UINT(2, i);

	return 1;
	
}

static int
test_get_opt_with_arg_found_long()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 	0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	0, 	0, 	"X2!",	0,	0},
	{"-x3",	"--xxx3", 	0, 	0, 	"X3!",	0,	0},
        {0,	0,		0,	0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "--xxx1"};

	i = 0;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(0, i);
	

	i = 1;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(1, i);

	i = 2;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NOT_NULL(option);
	CHECK_STRING("-x1", option->short_name);
	CHECK_STRING("--xxx1", optname);
	CHECK_NULL(arg);
	CHECK_UINT(1, option->count);
	CHECK_UINT(2, i);

	return 1;
	
}

static int
test_get_opt_with_arg_arg_present()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	"myarg",	0, 	"X2!",	0,	0},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "-x2", "argvalue"};

	i = 0;
	option = rdd_get_opt_with_arg(opttab, argv, 4, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(0, i);

	i = 1;
	option = rdd_get_opt_with_arg(opttab, argv, 4, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(1, i);

	i = 2;
	option = rdd_get_opt_with_arg(opttab, argv, 4, &i, &optname, &arg);
	CHECK_NOT_NULL(option);
	CHECK_STRING("-x2", option->short_name);
	CHECK_STRING("-x2", optname);
	CHECK_NOT_NULL(option->arg_value);
	CHECK_STRING("argvalue", option->arg_value);
	CHECK_UINT(1, option->count);
	CHECK_UINT(3, i);

	return 1;
	
}

static int
test_get_opt_with_arg_out()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--out", 	0	,	0, 	"X2!",	0,	0},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "--out"};

	i = 0;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(0, i);

	i = 1;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(1, i);

	i = 2;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NOT_NULL(option);
	CHECK_STRING("-x2", option->short_name);
	CHECK_STRING("--out", optname);
	CHECK_NULL(option->arg_value);
	CHECK_UINT(1, option->count);
	CHECK_UINT(2, i);

	return 1;
	
}

static int
test_get_opt_with_arg_out_count_nonzero()
{
	char * optname;
	char * arg;
	RDD_OPTION * option;
	unsigned int i;

	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--out", 	0	,	0, 	"X2!",	3,	0},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,			0,	0,	0} /* sentinel */
	};

	char * argv[] = {"yyy", "zzz", "--out"};

	i = 0;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(0, i);

	i = 1;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NULL(option);
	CHECK_NULL(optname);
	CHECK_NULL(arg);
	CHECK_UINT(1, i);

	i = 2;
	option = rdd_get_opt_with_arg(opttab, argv, 3, &i, &optname, &arg);
	CHECK_NOT_NULL(option);
	CHECK_STRING("-x2", option->short_name);
	CHECK_STRING("--out", optname);
	CHECK_NULL(option->arg_value);
	CHECK_UINT(4, option->count);
	CHECK_UINT(2, i);

	return 1;
	
}

static int
test_opt_set_arg_tab_null()
{
	char * arg;

	CHECK_INT(0, rdd_opt_set_arg(0, "longname", &arg));
	return 1;
}

static int
test_opt_set_arg_longname_null()
{
	char * arg;

	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	"myarg",	0, 	"X2!",	0,	"argvalue"},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,	0,	0,	0} /* sentinel */
	};

	CHECK_INT(0, rdd_opt_set_arg(opttab, 0, &arg));
	return 1;
}

static int
test_opt_set_arg_option_not_set()
{
	char * arg;

	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	"myarg",	0, 	"X2!",	0,	"argvalue"},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,	0,	0,	0} /* sentinel */
	};

	CHECK_INT(0, rdd_opt_set_arg(opttab, "xxx2", &arg)); 
	return 1;
}

static int
test_opt_set_arg_argp_null()
{
	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	"myarg",	0, 	"X2!",	1,	"argvalue"},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,	0,	0,	0} /* sentinel */
	};

	CHECK_INT(1, rdd_opt_set_arg(opttab, "xxx2", 0)); 
	return 1;
}

static int
test_opt_set_arg()
{
	char * arg;

	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	"myarg",	0, 	"X2!",	1,	"argvalue"},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,	0,	0,	0} /* sentinel */
	};

	CHECK_INT(1, rdd_opt_set_arg(opttab, "xxx2", &arg)); 
	CHECK_STRING("argvalue", arg);
	return 1;
}


static int
test_opt_set_tab_null()
{
	CHECK_INT(0, rdd_opt_set(0, "longname"));
	return 1;
}

static int
test_opt_set_longname_null()
{
	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	"myarg",	0, 	"X2!",	0,	"argvalue"},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,	0,	0,	0} /* sentinel */
	};

	CHECK_INT(0, rdd_opt_set(opttab, 0));
	return 1;
}

static int
test_opt_set_option_not_set()
{
	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	"myarg",	0, 	"X2!",	0,	"argvalue"},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,	0,	0,	0} /* sentinel */
	};

	CHECK_INT(0, rdd_opt_set(opttab, "xxx2")); 
	return 1;
}

static int
test_opt_set()
{
	RDD_OPTION opttab[] = {
	{"-x1",	"--xxx1", 	0, 		0, 	"X1!",	0,	0},
	{"-x2",	"--xxx2", 	"myarg",	0, 	"X2!",	1,	"argvalue"},
	{"-x3",	"--xxx3", 	0, 		0, 	"X3!",	0,	0},
        {0,	0,		0,		0,	0,	0,	0} /* sentinel */
	};

	CHECK_INT(1, rdd_opt_set(opttab, "xxx2")); 
	return 1;
}

static int
test_compare_paths_first_path_null()
{
	CHECK_INT(1, compare_paths(0, "somefile"));
	return 1;
}

static int
test_compare_paths_second_path_null()
{
	CHECK_INT(1, compare_paths("somefile", 0));
	return 1;
}

static int
test_compare_paths_both_null()
{
	CHECK_INT(1, compare_paths(0, 0));
	return 1;
}

static int
test_compare_paths_equal_nonexistent()
{
	CHECK_INT(1, compare_paths("nonexistent", "nonexistent"));
	return 1;
}

static int
test_compare_paths_equal_existent()
{
	CHECK_INT(0, compare_paths("simpletestfile.txt", "simpletestfile.txt"));
	return 1;
}

static int
test_compare_paths_different_paths_to_same_file()
{
	CHECK_INT(0, compare_paths("simpletestfile.txt", "tools/../simpletestfile.txt"));
	return 1;
}

static int
test_compare_paths_different_files()
{
	CHECK_INT(1, compare_paths("simpletestfile.txt", "8-jpeg-search"));
	return 1;
}


static int
call_tests(void)
{
	int result = 1;

	TEST(test_opt_init_null);
	TEST(test_opt_init);

	TEST(test_match_name_input_null);
	TEST(test_match_name_short_name_null_false);
	TEST(test_match_name_short_name_null_true);
	TEST(test_match_name_long_name_null_false);
	TEST(test_match_name_long_name_null_true);
	TEST(test_match_name_false);
	TEST(test_match_name_match_short);
	TEST(test_match_name_match_long);
	TEST(test_match_name_case);
	TEST(test_match_name_same_short_long);

	TEST(test_get_opt_with_arg_tab_null);
	TEST(test_get_opt_with_arg_argv_null);
	TEST(test_get_opt_with_arg_argc_nonpositive);
	TEST(test_get_opt_with_arg_i_null);
	TEST(test_get_opt_with_arg_i_too_large);
	TEST(test_get_opt_with_arg_i_negative);
	TEST(test_get_opt_with_arg_opt_null);
	TEST(test_get_opt_with_arg_arg_null);
	TEST(test_get_opt_with_arg_found_short);
	TEST(test_get_opt_with_arg_found_long);
	TEST(test_get_opt_with_arg_arg_present);
	// don't test argument not present; contains an exit
	// don't test count nonzero: contains an exit
	TEST(test_get_opt_with_arg_out);
	TEST(test_get_opt_with_arg_out_count_nonzero);

	TEST(test_opt_set_arg_tab_null);
	TEST(test_opt_set_arg_longname_null);
	TEST(test_opt_set_arg_option_not_set);
	TEST(test_opt_set_arg_argp_null);
	TEST(test_opt_set_arg);
	// don't test option not found; contains an exit

	TEST(test_opt_set_tab_null);
	TEST(test_opt_set_longname_null);
	TEST(test_opt_set_option_not_set);
	TEST(test_opt_set);
	// don't test option not found; contains an exit

	// don't test option_table_usage; is only text output on stderr
	// don't test opt_usage; contains an exit
	
	TEST(test_compare_paths_first_path_null);
	TEST(test_compare_paths_second_path_null);
	TEST(test_compare_paths_both_null);
	TEST(test_compare_paths_equal_nonexistent);
	TEST(test_compare_paths_equal_existent);
	TEST(test_compare_paths_different_paths_to_same_file);
	TEST(test_compare_paths_different_files);

	return result;
}

TEST_MAIN;
