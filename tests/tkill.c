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

static enum TestResult test_invalid_signal(void)
{
	if (linux_tkill((linux_pid_t)-1, linux_SIGRTMAX + 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_pid_t pid;
	if (linux_fork(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	if (!pid) // Child
	{
		linux_pause();
		linux_exit(0);
	}
	else // Parent
	{
		if (linux_tkill(pid, linux_SIGKILL))
		{
			// If the call fails, just leave the child as a dormant process.
			return TEST_RESULT_FAILURE;
		}

		int status = 0;
		if (linux_wait4((linux_pid_t)-1, &status, 0, 0, 0))
			return TEST_RESULT_OTHER_FAILURE;
	}

	return TEST_RESULT_SUCCESS;;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing tkill.\n");
	DO_TEST(invalid_signal, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing tkill.\n");

	return ret;
}
