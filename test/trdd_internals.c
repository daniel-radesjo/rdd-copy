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


/* A unit-test for netio. This file replaces the original ttcpwriter.c file, which is now called tpython_tcpwriter.c.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>



#include "rdd_internals.c"

#include "testhelper.h"

static char *progname;

static int
test_timeunits_secs_null()
{
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_BADARG, timeUnits(100, 0, &mins, &hours, &days));
	return 1;
}

static int
test_timeunits_mins_null()
{
	int secs;
	int hours;
	int days;
	
	CHECK_UINT(RDD_BADARG, timeUnits(100, &secs, 0, &hours, &days));
	return 1;
}

static int
test_timeunits_hours_null()
{
	int secs;
	int mins;
	int days;
	
	CHECK_UINT(RDD_BADARG, timeUnits(100, &secs, &mins, 0, &days));
	return 1;
}

static int
test_timeunits_days_null()
{
	int secs;
	int mins;
	int hours;
	
	CHECK_UINT(RDD_BADARG, timeUnits(100, &secs, &mins, &hours, 0));
	return 1;
}

static int
test_timeunits_0()
{
	int secs;
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_OK, timeUnits(0, &secs, &mins, &hours, &days));
	CHECK_UINT(0, secs);
	CHECK_UINT(0, mins);
	CHECK_UINT(0, hours);
	CHECK_UINT(0, days);
	return 1;
}

static int
test_timeunits_secsonly()
{
	int secs;
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_OK, timeUnits(3, &secs, &mins, &hours, &days));

	CHECK_UINT(3, secs);
	CHECK_UINT(0, mins);
	CHECK_UINT(0, hours);
	CHECK_UINT(0, days);
	return 1;
}

static int
test_timeunits_minsonly()
{
	int secs;
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_OK, timeUnits(120, &secs, &mins, &hours, &days));

	CHECK_UINT(0, secs);
	CHECK_UINT(2, mins);
	CHECK_UINT(0, hours);
	CHECK_UINT(0, days);
	return 1;
}

static int
test_timeunits_hoursonly()
{
	int secs;
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_OK, timeUnits(3600, &secs, &mins, &hours, &days));

	CHECK_UINT(0, secs);
	CHECK_UINT(0, mins);
	CHECK_UINT(1, hours);
	CHECK_UINT(0, days);
	return 1;
}

static int
test_timeunits_daysonly()
{
	int secs;
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_OK, timeUnits(5 * 24 * 3600, &secs, &mins, &hours, &days));

	CHECK_UINT(0, secs);
	CHECK_UINT(0, mins);
	CHECK_UINT(0, hours);
	CHECK_UINT(5, days);
	return 1;
}

static int
test_timeunits_secsandmins()
{
	int secs;
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_OK, timeUnits(67, &secs, &mins, &hours, &days));

	CHECK_UINT(7, secs);
	CHECK_UINT(1, mins);
	CHECK_UINT(0, hours);
	CHECK_UINT(0, days);
	return 1;
}

static int
test_timeunits_allunits()
{
	int secs;
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_OK, timeUnits(28*3600 + 198, &secs, &mins, &hours, &days));

	CHECK_UINT(18, secs);
	CHECK_UINT(3, mins);
	CHECK_UINT(4, hours);
	CHECK_UINT(1, days);
	return 1;
}

static int
test_timeunits_fraction()
{
	int secs;
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_OK, timeUnits(28*3600 + 198 + 0.31, &secs, &mins, &hours, &days));

	CHECK_UINT(18, secs);
	CHECK_UINT(3, mins);
	CHECK_UINT(4, hours);
	CHECK_UINT(1, days);
	return 1;
}

static int
test_timeunits_negative()
{
	int secs;
	int mins;
	int hours;
	int days;
	
	CHECK_UINT(RDD_OK, timeUnits(-61, &secs, &mins, &hours, &days));

	CHECK_UINT(-1, secs);
	CHECK_UINT(-1, mins);
	CHECK_UINT(0, hours);
	CHECK_UINT(0, days);
	return 1;
}

static int
call_tests(void)
{
	int result = 1;

	TEST(test_timeunits_secs_null);
	TEST(test_timeunits_mins_null);
	TEST(test_timeunits_hours_null);
	TEST(test_timeunits_days_null);
	TEST(test_timeunits_0);
	TEST(test_timeunits_secsonly);
	TEST(test_timeunits_minsonly);
	TEST(test_timeunits_hoursonly);
	TEST(test_timeunits_daysonly);
	TEST(test_timeunits_secsandmins);
	TEST(test_timeunits_allunits);
	TEST(test_timeunits_fraction);
	TEST(test_timeunits_negative);

	return result;
}

TEST_MAIN;
