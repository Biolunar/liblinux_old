#include "test.h"

#include <liblinux/linux.h>

#include <unistd.h>

static enum TestResult test_invalid_array(void)
{
	unsigned int ret = 0;
	if (linux_poll(0, 0, 0, &ret) || ret != 0)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_timeout(void)
{
	int p[2] = { -1, -1 };
	if (pipe(p) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_pollfd_t pfd =
	{
		.fd = p[1],
		.events = linux_POLLIN,
		.revents = 0,
	};
	unsigned int ret = 0;
	if (linux_poll(&pfd, 1, 100, &ret) || ret != 0 || pfd.revents != 0) // Wait for 0.1 second.
	{
		close(p[0]);
		close(p[1]);
		return TEST_RESULT_FAILURE;
	}

	close(p[0]);
	close(p[1]);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing poll.\n");
	DO_TEST(invalid_array, &ret);
	DO_TEST(timeout, &ret);
	printf("Finished testing poll.\n");

	return ret;
}
