#include "test.h"

#include <stdio.h>
#include <stdlib.h>

#include <liblinux/linux.h>

static enum TestResult test_correct_usage(void)
{
	if  (linux_sched_yield())
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing sched_yield.\n");
	DO_TEST(correct_usage, &ret);
	printf("Finished testing sched_yield.\n");

	return ret;
}
