#include "test.h"

#include <liblinux/linux.h>

static size_t const size = sizeof(linux_sigset_t);

static enum TestResult test_invalid_size(void)
{
	if (linux_rt_sigprocmask(linux_SIG_BLOCK, 0, 0, size - 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	if (linux_rt_sigprocmask(linux_SIG_BLOCK, 0, 0, size + 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_how(void)
{
	linux_sigset_t empty;
	linux_sigemptyset(&empty);

	if (linux_rt_sigprocmask(linux_SIG_BLOCK - 1, &empty, 0, size) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	if (linux_rt_sigprocmask(linux_SIG_SETMASK + 1, &empty, 0, size) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_get_old(void)
{
	linux_sigset_t old;
	if (linux_rt_sigprocmask(0, 0, &old, size))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing rt_sigprocmask.\n");
	DO_TEST(invalid_size, &ret);
	DO_TEST(invalid_how, &ret);
	DO_TEST(get_old, &ret);
	printf("Finished testing rt_sigprocmask.\n");

	return ret;
}
