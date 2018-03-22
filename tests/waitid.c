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

#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static enum TestResult test_no_child(void)
{
	struct linux_siginfo_t info;
	struct linux_rusage_t usage;
	if  (linux_waitid(linux_P_ALL, 0, &info, linux_WEXITED, &usage) != linux_ECHILD)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_option(void)
{
	struct linux_siginfo_t info;
	struct linux_rusage_t usage;
	if  (linux_waitid(linux_P_ALL, 0, &info, ~(linux_WNOHANG | linux_WUNTRACED | linux_WCONTINUED | linux_WNOTHREAD | linux_WALL | linux_WCLONE), &usage) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	pid_t const pid = fork();
	if (pid == -1)
		return TEST_RESULT_OTHER_FAILURE;
	else if (!pid) // child
		linux_exit(42);
	else // parent
	{
		struct linux_siginfo_t info;
		struct linux_rusage_t usage;
		enum linux_error_t err = linux_waitid(linux_P_ALL, 0, &info, linux_WEXITED, &usage);
		if (err)
		{
			printf("err: %d\n", err);
			return TEST_RESULT_FAILURE;
		}

		return TEST_RESULT_SUCCESS;
	}
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing waitid.\n");
	DO_TEST(no_child, &ret);
	DO_TEST(invalid_option, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing waitid.\n");

	return ret;
}
