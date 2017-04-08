#include "test.h"

#include <liblinux/linux.h>

static enum TestResult test_invalid_file(void)
{
	if (linux_lstat("some very non existant name", 0) != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	if (linux_lstat("", 0) != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	if (linux_lstat(0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_real_file(void)
{
	struct linux_stat_t stat;
	if (linux_lstat("/proc/self/maps", &stat))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing lstat.\n");
	DO_TEST(invalid_file, &ret);
	DO_TEST(real_file, &ret);
	printf("Finished testing lstat.\n");

	return ret;
}
