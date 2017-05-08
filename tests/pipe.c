#include "test.h"

#include <stdio.h>
#include <stdlib.h>

#include <liblinux/linux.h>

#include <unistd.h>

static enum TestResult test_invalid_fd(void)
{
	if (linux_pipe(0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_valid_function(void)
{
	linux_fd_t p[2];
	if (linux_pipe(p))
		return TEST_RESULT_FAILURE;

	if (p[0] != (linux_stderr + 1) || p[1] != (linux_stderr + 2))
		return TEST_RESULT_FAILURE;

	close((int)p[0]);
	close((int)p[1]);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing pipe.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(valid_function, &ret);
	printf("Finished testing pipe.\n");

	return ret;
}
