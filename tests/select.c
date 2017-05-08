#include "test.h"

#include <stdio.h>
#include <stdlib.h>

#include <liblinux/linux.h>

static enum TestResult test_invalid_number(void)
{
	if (linux_select(-1, 0, 0, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_timeout(void)
{
	struct linux_timeval_t tv =
	{
		.tv_sec = -1,
		.tv_usec = -1,
	};
	if (linux_select(0, 0, 0, 0, &tv, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_timeval_t tv =
	{
		.tv_sec = 1,
		.tv_usec = 0,
	};
	linux_fd_set_t set;
	linux_FD_ZERO(&set);
	linux_FD_SET(linux_stdout, &set);
	linux_FD_SET(linux_stderr, &set);
	unsigned int n = 0;
	if (linux_select(3, 0, &set, 0, &tv, &n) || n != 2)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing select.\n");
	DO_TEST(invalid_number, &ret);
	DO_TEST(invalid_timeout, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing select.\n");

	return ret;
}
