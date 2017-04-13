#include "test.h"

#include <limits.h>

#include <liblinux/linux.h>

#include <sys/mman.h>

static enum TestResult test_invalid_address(void)
{
	if (linux_mprotect(0, sizeof(int), linux_PROT_READ | linux_PROT_WRITE) != linux_ENOMEM)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_use(void)
{
	size_t const size = sizeof(int);
	void* addr = 0;
	// TODO: Using linux_mmap here because MAP_ANONYMOUS needs a feature test macro.
	if (linux_mmap(0, size, linux_PROT_NONE, linux_MAP_PRIVATE | linux_MAP_ANONYMOUS, 0, 0, &addr))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_mprotect(addr, size, linux_PROT_READ | linux_PROT_WRITE))
		return TEST_RESULT_FAILURE;

	if (munmap(addr, size) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing mprotect.\n");
	DO_TEST(invalid_address, &ret);
	DO_TEST(correct_use, &ret);
	printf("Finished testing mprotect.\n");

	return ret;
}
