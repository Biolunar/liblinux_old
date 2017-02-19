#ifndef HEADER_LIBLINUX_TESTS_TEST_H_INCLUDED
#define HEADER_LIBLINUX_TESTS_TEST_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>

enum TestResult
{
	TEST_RESULT_SUCCESS,
	TEST_RESULT_FAILURE,
	TEST_RESULT_OTHER_FAILURE,

	TEST_RESULT_MAX,
};

static inline void do_test(enum TestResult test(void), char const* name, int result[static 1])
{
	printf(u8"\tTesting %s… ", name);
	enum TestResult const ret = test();
	switch (ret)
	{
		case TEST_RESULT_SUCCESS: printf(u8"SUCCESS\n"); break;
		case TEST_RESULT_FAILURE: printf(u8"FAILURE\n"); break;
		default: printf(u8"OTHER FAILURE\n"); break;
	}

	if (ret)
		*result = EXIT_FAILURE;
}

#define DO_TEST(name, ret)                           \
	do {                                         \
		do_test(test_ ## name, # name, ret); \
	} while (0)

#endif // !HEADER_LIBLINUX_TESTS_TEST_H_INCLUDED
