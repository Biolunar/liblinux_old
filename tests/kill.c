/*
 * Copyright 2017 Mahdi Khanalizadeh
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static enum TestResult test_invalid_signal(void)
{
	if (linux_kill(-1, linux_SIGRTMAX + 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	pid_t const pid = fork();
	if (pid == -1)
		return TEST_RESULT_OTHER_FAILURE;
	else if (!pid) // Child
	{
		linux_pause();
		linux_exit(0);
	}
	else // Parent
	{
		if (linux_kill(pid, linux_SIGKILL))
		{
			// If the call fails, just leave the child as a dormant process.
			return TEST_RESULT_FAILURE;
		}

		int status = 0;
		wait(&status);
	}

	return TEST_RESULT_SUCCESS;;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing kill.\n");
	DO_TEST(invalid_signal, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing kill.\n");

	return ret;
}
