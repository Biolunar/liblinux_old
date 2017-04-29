#include "test.h"

#include <liblinux/linux.h>

#include <unistd.h>

static enum TestResult test_valid_file(void)
{
	if (linux_access("/dev/null", linux_R_OK))
		return TEST_RESULT_FAILURE;

	if (linux_access("/dev/zero", linux_W_OK))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_no_permission(void)
{
	if (linux_access("/", linux_W_OK) != linux_EACCES)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_path(void)
{
	if (linux_access(0, linux_W_OK) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	if (linux_access("some very non existant name", linux_R_OK) != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_mode(void)
{
	if (linux_access("/dev/null", (linux_R_OK | linux_W_OK | linux_X_OK) + 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing access.\n");
	DO_TEST(valid_file, &ret);
	DO_TEST(no_permission, &ret);
	DO_TEST(invalid_path, &ret);
	DO_TEST(invalid_mode, &ret);
	printf("Finished testing access.\n");

	return ret;
}
