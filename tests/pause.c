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

#include <sys/types.h>
#include <unistd.h>

static void handler(int const sig)
{
	(void)sig;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_sigaction_t sa =
	{
		.sa_handler = &handler,
		.sa_flags = linux_SA_RESTORER | linux_SA_RESTART,
		.sa_restorer = linux_rt_sigreturn,
	};
	if (linux_rt_sigaction(linux_SIGUSR1, &sa, 0, sizeof(linux_sigset_t)))
		return TEST_RESULT_OTHER_FAILURE;

	// Block all signals except SIGUSR1 so that no foreign signal kills parent nor child.
	linux_sigset_t set;
	linux_sigfillset(&set);
	linux_sigdelset(&set, linux_SIGUSR1);
	if (linux_rt_sigprocmask(linux_SIG_BLOCK, &set, 0, sizeof(linux_sigset_t)))
		return TEST_RESULT_OTHER_FAILURE;

	pid_t const pid = fork();
	if (pid == -1)
		return TEST_RESULT_OTHER_FAILURE;
	else if (!pid) // Child
	{
		pid_t const parent = getppid();
		while (1)
			linux_kill(parent, linux_SIGUSR1);
	}
	else // Parent
	{
		if (linux_pause() != linux_EINTR)
			return TEST_RESULT_FAILURE;

		linux_kill(pid, linux_SIGKILL);
		linux_wait4(-1, 0, 0, 0, 0);
	}

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing pause.\n");
	DO_TEST(correct_usage, &ret);
	printf("Finished testing pause.\n");

	return ret;
}
