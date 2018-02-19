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

static uint8_t const exit_code = 42;

static enum TestResult test_correct_usage(void)
{
	linux_pid_t pid = -1;
	if  (linux_fork(&pid))
		return TEST_RESULT_FAILURE;
	if (!pid) // child
	{
		linux_exit(exit_code);
	}
	else // parent
	{
		int status = 0;
		if (linux_wait4(-1, &status, 0, 0, 0))
			return TEST_RESULT_OTHER_FAILURE;

		if (!linux_WIFEXITED(status) || linux_WEXITSTATUS(status) != exit_code)
			return TEST_RESULT_FAILURE;

		return TEST_RESULT_SUCCESS;
	}
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing fork.\n");
	DO_TEST(correct_usage, &ret);
	printf("Finished testing fork.\n");

	return ret;
}
