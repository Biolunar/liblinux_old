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

static char const* progname;
static char const* const param1 = "hello";
static char const* const param2 = "world";
static char const* const env = "key=value";

static enum TestResult test_segfault(void)
{
	char const* argv_ok[] = { progname, 0 };
	char const* argv_bad[] = { (char const*)1, 0 };
	char const* envp_ok[] = {0};
	char const* envp_bad[] = { (char const*)1, 0 };

	if (linux_execve(0, argv_ok, envp_ok) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	if (linux_execve(progname, argv_bad, envp_ok) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	if (linux_execve(progname, argv_ok, envp_bad) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	pid_t const pid = fork();
	if (pid == -1) // error
		return TEST_RESULT_OTHER_FAILURE;
	else if (!pid) // child
	{
		char const* const argv[] = { progname, param1, param2, 0 };
		char const* const envp[] = { env, 0 };
		linux_execve(progname, argv, envp);
		// If the program goes this far, the syscall failed.
		linux_exit(EXIT_FAILURE);
	}
	else // parent
	{
		int status = 0;
		if (linux_wait4(-1, &status, 0, 0, 0))
			return TEST_RESULT_OTHER_FAILURE;

		if (linux_WIFEXITED(status) && linux_WEXITSTATUS(status) == 42)
			return TEST_RESULT_SUCCESS;

		return TEST_RESULT_FAILURE;
	}
}

int main(int argc, char* argv[])
{
	if (argc > 2)
	{
		if (strcmp(argv[1], param1) || strcmp(argv[2], param2) || strcmp(getenv("key"), "value"))
			return EXIT_FAILURE;

		return 42;
	}
	if (argc > 1)
			return EXIT_FAILURE;
	progname = argv[0];

	int ret = EXIT_SUCCESS;

	printf("Start testing execve.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing execve.\n");

	return ret;
}
