#include "test.h"

#include <liblinux/linux.h>

#include <unistd.h>

static enum TestResult test_invalid_fd(void)
{
	if (linux_ioctl(linux_stdout, 0, 0, 0) != linux_ENOTTY)
		return TEST_RESULT_FAILURE;

	if (linux_ioctl(linux_stderr + 1, 0, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing ioctl.\n");
	DO_TEST(invalid_fd, &ret);
	printf("Finished testing ioctl.\n");

	return ret;
}
