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

static enum TestResult test_invalid_pid(void)
{
	linux_pid_t sid;
	if (linux_getsid((linux_pid_t)-1, &sid) != linux_ESRCH)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_pid_t pid;
	if (linux_getpid(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	linux_pid_t sid;

	if (linux_getsid(0, &sid))
		return TEST_RESULT_FAILURE;

	if (linux_getsid(pid, &sid))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing getsid.\n");
	DO_TEST(invalid_pid, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing getsid.\n");

	return ret;
}
