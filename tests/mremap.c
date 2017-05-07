#include "test.h"

#include <limits.h>

#include <liblinux/linux.h>

#include <sys/mman.h>

static size_t const size = 0x1000;

static enum TestResult test_invalid_alignment(void)
{
	if (linux_mremap((void*)1, size, size * 2, linux_MREMAP_MAYMOVE, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_address(void)
{
	if (linux_mremap(0, size, size * 2, linux_MREMAP_MAYMOVE, 0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	void* addr = 0;
	// TODO: Using linux_mmap here because MAP_ANONYMOUS needs a feature test macro.
	if (linux_mmap(0, size, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &addr))
		return TEST_RESULT_OTHER_FAILURE;

	void* new_addr = 0;
	if (linux_mremap(addr, size, size * 2, linux_MREMAP_MAYMOVE, 0, &new_addr))
	{
		linux_munmap(addr, size);
		return TEST_RESULT_FAILURE;
	}
	if (!new_addr)
	{
		linux_munmap(addr, size);
		return TEST_RESULT_FAILURE;
	}

	linux_munmap(addr, size);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing mremap.\n");
	DO_TEST(invalid_alignment, &ret);
	DO_TEST(invalid_address, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing mremap.\n");

	return ret;
}
