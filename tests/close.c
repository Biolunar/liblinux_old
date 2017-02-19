#include "test.h"

#include <liblinux/linux.h>

static enum TestResult test_valid_fd(void)
{
	if (linux_close(0))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_fd(void)
{
	if (linux_close(3) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing close.\n");
	DO_TEST(valid_fd, &ret);
	DO_TEST(invalid_fd, &ret);
	printf("Finished testing close.\n");

	return ret;
}
