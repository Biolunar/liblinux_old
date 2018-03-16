/*
 * Copyright 2018 Mahdi Khanalizadeh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "test.h"
#include <liblinux/linux.h>

#include <stdio.h>
#include <stdlib.h>

static enum TestResult test_invalid_id(void)
{
	struct linux_timespec_t const request = { .tv_nsec = 1, };
	struct linux_timespec_t remain;
	if (linux_clock_nanosleep(linux_CLOCK_REALTIME - 1, 0, &request, &remain) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_segfault(void)
{
	struct linux_timespec_t remain;
	if (linux_clock_nanosleep(linux_CLOCK_MONOTONIC, 0, (struct linux_timespec_t*)-1, &remain) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_timespec_t const request = { .tv_nsec = 1, };
	struct linux_timespec_t remain;
	if (linux_clock_nanosleep(linux_CLOCK_MONOTONIC, 0, &request, &remain))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing clock_nanosleep.\n");
	DO_TEST(invalid_id, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing clock_nanosleep.\n");

	return ret;
}
