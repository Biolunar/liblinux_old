#include "test.h"

#include <limits.h>
#include <stdint.h>

#include <liblinux/linux.h>

static enum TestResult test_invalid_address(void)
{
	void* base = 0;
	if (linux_brk(0, &base))
		return TEST_RESULT_FAILURE;

	void* ret = 0;
	if (linux_brk((void*)UINTPTR_MAX, &ret) || base != ret)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_alloc(void)
{
	void* base = 0;
	if (linux_brk(0, &base))
		return TEST_RESULT_FAILURE;

	size_t const size = sizeof(int);
	void* ret = 0;
	if (linux_brk((char*)base + size, &ret) || ret != ((char*)base + size))
		return TEST_RESULT_FAILURE;

	int volatile* const p = ret;
	*p = INT_MAX;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing brk.\n");
	DO_TEST(invalid_address, &ret);
	DO_TEST(alloc, &ret);
	printf("Finished testing brk.\n");

	return ret;
}
