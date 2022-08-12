#ifndef __testhelper_h__
#define __testhelper_h__

#include <sys/wait.h>

static int g_test_count = 0;
static int g_failed_test_count = 0;

#define RDDCOPY "../src/rdd-copy "
#define REDIRECT " 1>/dev/null 2>/dev/null"

#define COMMANDLINE(args) (RDDCOPY args REDIRECT)
#define COMMANDLINE_BG(args) (RDDCOPY args REDIRECT " &")
#define MAX_TESTNAME_LENGTH 80

#define TEST(testFunc) \
{ \
	++g_test_count; \
	int __rc = testFunc(); \
	int __i; \
	printf(#testFunc); \
	/* align */ \
	if (strlen(#testFunc)>MAX_TESTNAME_LENGTH) { \
		printf("\nTest function name too long\n"); \
		result = 0; \
	} else { \
		for (__i=0; __i<MAX_TESTNAME_LENGTH-strlen(#testFunc); __i++) { \
			printf("."); \
		} \
		if (__rc) { \
			printf(" ok\n"); \
		} \
		else { \
			printf(" FAILED\n"); \
			++g_failed_test_count; \
		} \
		result = result && __rc; \
	} \
}

#define SAFE_TEST(test_func)\
{\
	CHECK_TRUE(setup());\
	TEST(test_func);\
	CHECK_TRUE(teardown());\
}\

#define CHECK_TRUE(__func) \
{ \
	int __rc = __func; \
	if (!__rc) { \
		printf(#__func": expected true value\n"); \
		return 0; \
	}\
}

#define CHECK_NULL(__func) \
{ \
	void * __rc = __func; \
	if (__rc != 0) { \
		printf(#__func": expected null value\n"); \
		return 0; \
	} \
}

#define CHECK_NULL_GOTO(__func) \
{ \
	void * __rc = __func; \
	if (__rc != 0) { \
		printf(#__func": expected null value\n"); \
		goto error; \
	} \
}

#define CHECK_NOT_NULL(__func) \
{ \
	void * __rc = __func; \
	if (__rc == 0) { \
		printf(#__func": expected non-null value\n"); \
		return 0; \
	} \
}

#define CHECK_NOT_NULL_GOTO(__func) \
{ \
	void * __rc = __func; \
	if (__rc == 0) { \
		printf(#__func": expected non-null value\n"); \
		goto error; \
	} \
}

#define CHECK_INT(__expected,__func) \
{ \
	int __rc = __func; \
	if (__expected != __rc) { \
		printf(#__func": expected %u instead of %d\n", __expected, __rc); \
		return 0; \
	} \
}

#define CHECK_INT_GOTO(__expected,__func) \
{ \
	int __rc = __func; \
	if (__expected != __rc) { \
		printf(#__func": expected %u instead of %u\n", __expected, __rc); \
		goto error; \
	} \
}

#define CHECK_UINT(__expected,__func) \
{ \
	unsigned int __rc = __func; \
	if (__expected != __rc) { \
		printf(#__func": expected %u instead of %u\n", __expected, __rc); \
		return 0; \
	} \
}

#define CHECK_UINT_GOTO(__expected,__func) \
{ \
	unsigned int __rc = __func; \
	if (__expected != __rc) { \
		printf(#__func": expected %u instead of %u\n", __expected, __rc); \
		goto error; \
	} \
}

#define CHECK_UINT64(__expected,__func) \
{ \
	unsigned long long __rc = __func; \
	if (__expected != __rc) { \
		printf(#__func": expected %llu instead of %llu\n", __expected, __rc); \
		return 0; \
	} \
}

#define CHECK_UINT64_GOTO(__expected,__func) \
{ \
	unsigned long long __rc = __func; \
	if (__expected != __rc) { \
		printf(#__func": expected %llu instead of %llu\n", __expected, __rc); \
		goto error; \
	} \
}

#define CHECK_UCHAR_ARRAY(__expected,__value,__size) \
{ \
	int __i; \
	for (__i=0; __i<__size; __i++) { \
		if (__expected[__i] != __value[__i])  { \
			printf("array index %d: expected %u instead of %u\n", __i, __expected[__i], __value[__i]); \
			return 0; \
		} \
	} \
}

#define CHECK_UCHAR_ARRAY_GOTO(__expected,__value,__size) \
{ \
	int __i; \
	for (__i=0; __i<__size; __i++) { \
		if (__expected[__i] != __value[__i])  { \
			printf("array index %d: expected %u instead of %u\n", __i, __expected[__i], __value[__i]); \
			goto error; \
		} \
	} \
}

#define CHECK_EXITSTATUS(__expected,__func) \
{ \
	int __rc = WEXITSTATUS(__func); \
	if (__expected != __rc) { \
		printf(#__func": expected %d instead of %d\n", __expected, __rc); \
		return 0; \
	} \
}

#define CHECK_EXITSTATUS_GOTO(__expected,__func) \
{ \
	int __rc = WEXITSTATUS(__func); \
	if (__expected != __rc) { \
		printf(#__func": expected %d instead of %d\n", __expected, __rc); \
		goto error; \
	} \
}

// to prevent 'unused' warnings
#define IGNORE_RESULT(__func) \
{ \
	int __rc = __func; \
	__rc = 0; \
}

#define CHECK_STRING(__expected,__value) \
{ \
	if (strcmp(__expected, __value)) { \
		printf("expected '%s' instead of '%s'\n", __expected, __value); \
	} \
}

#define TEST_MAIN \
static char * progname; \
\
static void \
command_line(int argc, char **argv) \
{ \
	if (argc != 1) { \
		fprintf(stderr, "Usage: %s\n", progname); \
		exit(EXIT_FAILURE); \
	} \
} \
\
static int \
run_tests(void) \
{ \
	int result = 1; \
	printf("running %s\n", progname); \
\
	result = call_tests(); \
\
	printf("\nDone running %d tests; %d failed.\n", g_test_count, g_failed_test_count); \
	if (result) { \
		printf("\n%s ok\n", progname); \
	}  \
	else { \
		printf("\n%s FAILED\n", progname); \
	} \
	printf("\n_______________________________________________________________\n\n\n"); \
	return result; \
} \
\
int \
main(int argc, char **argv) \
{ \
	progname = argv[0]; \
\
	command_line(argc, argv); \
\
	int result = run_tests(); \
	if (result) { \
		return EXIT_SUCCESS; \
	} \
	else { \
		return EXIT_FAILURE; \
	} \
}
int deleteFiles(const char * fileList[], int len);

int deleteFiles(const char * fileList[], int len)
{
	int result = EXIT_SUCCESS;
	int rc;
	int i;
	char command[1024];
	for (i=0; i<len; i++) {
		if (snprintf(command, sizeof(command), "rm -f %s", fileList[i]) >= sizeof(command)) {
			printf("String too long!\n");
			exit(1); 
		}
		rc = system(command);
		if (rc != EXIT_SUCCESS) {
			// store return code, but continue deleting files
			result = rc;
		}
	}
	return result;
}

#endif // __testhelper_h__
