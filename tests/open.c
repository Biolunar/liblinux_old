#include "test.h"

#include <unistd.h>

#include <liblinux/linux.h>

static enum TestResult test_opening_file(void)
{
	linux_fd_t fd = 0;
	if (linux_open("/dev/urandom", linux_O_RDONLY, 0, &fd))
		return TEST_RESULT_FAILURE;

	if (close((int)fd) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_creating_file(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;
	char const* const filename = "tmp_file";

	linux_fd_t fd = 0;
	if (linux_open(filename, linux_O_RDWR | linux_O_CLOEXEC | linux_O_CREAT | linux_O_EXCL, linux_S_IRUSR | linux_S_IWUSR, &fd))
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	if (unlink(filename) == -1)
		goto cleanup;

	ret = TEST_RESULT_SUCCESS;

cleanup:
	close((int)fd);
	return ret;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing open.\n");
	DO_TEST(opening_file, &ret);
	DO_TEST(creating_file, &ret);
	printf("Finished testing open.\n");

	return ret;
}
