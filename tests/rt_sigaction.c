#include "test.h"

#include <liblinux/linux.h>

static enum TestResult test_handler(void);

static size_t const size = sizeof(linux_sigset_t);
static int volatile condition = 0;

static enum TestResult test_invalid_signum(void)
{
	if (linux_rt_sigaction(0, 0, 0, size) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_size(void)
{
	if (linux_rt_sigaction(linux_SIGUSR1, 0, 0, size - 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	if (linux_rt_sigaction(linux_SIGUSR1, 0, 0, size + 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_get_old(void)
{
	struct linux_sigaction_t old;
	if (linux_rt_sigaction(linux_SIGUSR1, 0, &old, size))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static void normal_handler(int const signum)
{
	(void)signum;
	condition = 1;
}

static enum TestResult test_set_new(void)
{
	linux_sigset_t empty = 0;
	linux_sigemptyset(&empty);
	struct linux_sigaction_t const new =
	{
		.sa_handler = &normal_handler,
		.sa_flags = linux_SA_RESTORER,
		.sa_restorer = linux_restorer,
		.sa_mask = empty,
	};
	if (linux_rt_sigaction(linux_SIGUSR1, &new, 0, size))
		return TEST_RESULT_FAILURE;

	condition = 0;
	enum TestResult const ret = test_handler();
	if (ret != TEST_RESULT_SUCCESS)
		return ret;

	return TEST_RESULT_SUCCESS;
}

static void siginfo_handler(int const signum, struct linux_siginfo_t* const info, void* const context)
{
	(void)signum;
	(void)info;
	(void)context;

	condition = 1;
}

static enum TestResult test_set_siginfo(void)
{
	linux_sigset_t empty = 0;
	linux_sigemptyset(&empty);
	struct linux_sigaction_t const new =
	{
		.sa_handler = (linux_sighandler_t)&siginfo_handler,
		.sa_flags = linux_SA_RESTORER | linux_SA_SIGINFO,
		.sa_restorer = linux_restorer,
		.sa_mask = empty,
	};
	if (linux_rt_sigaction(linux_SIGUSR1, &new, 0, size))
		return TEST_RESULT_FAILURE;

	condition = 0;
	enum TestResult const ret = test_handler();
	if (ret != TEST_RESULT_SUCCESS)
		return ret;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing rt_sigaction.\n");
	DO_TEST(invalid_signum, &ret);
	DO_TEST(invalid_size, &ret);
	DO_TEST(get_old, &ret);
	DO_TEST(set_new, &ret);
	DO_TEST(set_siginfo, &ret);
	printf("Finished testing rt_sigaction.\n");

	return ret;
}

// Includes are this late because we don't trust the libc to fuck our code up with macros.
#include <signal.h>

static enum TestResult test_handler(void)
{
	if (condition)
		return TEST_RESULT_OTHER_FAILURE;

	raise(SIGUSR1);
	if (!condition)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}
