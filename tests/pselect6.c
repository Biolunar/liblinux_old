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

static enum TestResult test_invalid_number(void)
{
	if (linux_pselect6(-1, 0, 0, 0, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_timeout(void)
{
	struct linux_timespec_t ts =
	{
		.tv_sec = -1,
		.tv_nsec = -1,
	};
	if (linux_pselect6(0, 0, 0, 0, &ts, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_timespec_t ts =
	{
		.tv_sec = 1,
		.tv_nsec = 0,
	};
	linux_fd_set_t set;
	linux_FD_ZERO(&set);
	linux_FD_SET(linux_stdout, &set);
	linux_FD_SET(linux_stderr, &set);
	unsigned int n = 0;
	if (linux_pselect6(3, 0, &set, 0, &ts, 0, &n) || n != 2)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing pselect6.\n");
	DO_TEST(invalid_number, &ret);
	DO_TEST(invalid_timeout, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing pselect6.\n");

	return ret;
}
