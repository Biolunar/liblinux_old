#include "test.h"

#include <limits.h>

#include <liblinux/linux.h>

#include <sys/mman.h>

static enum TestResult test_invalid_file(void)
{
	int const fd = -1;
	if (linux_mmap(0, sizeof(int), linux_PROT_READ, linux_MAP_PRIVATE, (linux_fd_t)fd, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_length(void)
{
	if (linux_mmap(0, 0, linux_PROT_READ, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_visibility(void)
{
	if (linux_mmap(0, sizeof(int), linux_PROT_READ, linux_MAP_ANONYMOUS, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	if (linux_mmap(0, sizeof(int), linux_PROT_READ, linux_MAP_PRIVATE | linux_MAP_SHARED | linux_MAP_ANONYMOUS, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_alloc(void)
{
	void* ret = 0;
	size_t const length = sizeof(int);
	if (linux_mmap(0, length, linux_PROT_WRITE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &ret))
		return TEST_RESULT_FAILURE;

	int volatile* const p = ret;
	*p = INT_MAX;

	if (munmap(ret, length) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing mmap.\n");
	DO_TEST(invalid_file, &ret);
	DO_TEST(invalid_length, &ret);
	DO_TEST(invalid_visibility, &ret);
	DO_TEST(alloc, &ret);
	printf("Finished testing mmap.\n");

	return ret;
}
