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

static enum TestResult test_correct_usage(void)
{
	// Before becoming a session leader the process must cease to be a
	// process group leader. Therefore make this process a member of the
	// parents process group.

	linux_pid_t ppid;
	if (linux_getppid(&ppid))
		return TEST_RESULT_OTHER_FAILURE;

	linux_pid_t pgid;
	if (linux_getpgid(ppid, &pgid))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_setpgid(0, pgid))
		return TEST_RESULT_OTHER_FAILURE;

	linux_pid_t sid;
	if (linux_setsid(&sid))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing setsid.\n");
	DO_TEST(correct_usage, &ret);
	printf("Finished testing setsid.\n");

	return ret;
}
