#include "test.h"

#include <limits.h>

#include <liblinux/linux.h>

#include <sys/mman.h>

static enum TestResult test_invalid_address(void)
{
	// Address 0x1 is not aligned to a page boundary.
	if (linux_munmap((void*)1, sizeof(int)) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_use(void)
{
	size_t const size = sizeof(int);
	void* addr = 0;
	// TODO: Using linux_mmap here because MAP_ANONYMOUS needs a feature test macro.
	if (linux_mmap(0, size, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &addr))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_munmap(addr, size))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing munmap.\n");
	DO_TEST(invalid_address, &ret);
	DO_TEST(correct_use, &ret);
	printf("Finished testing munmap.\n");

	return ret;
}
