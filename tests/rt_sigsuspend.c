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

static void signal_handler(int const sig)
{
	(void)sig;
}

static enum TestResult test_segfault(void)
{
	if (linux_rt_sigsuspend(0, sizeof(linux_sigset_t)) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_sigaction_t act =
	{
		.sa_handler = &signal_handler,
		.sa_flags = linux_SA_RESTORER,
		.sa_restorer = &linux_rt_sigreturn,
	};
	linux_sigemptyset(&act.sa_mask);
	if (linux_rt_sigaction(linux_SIGUSR1, &act, 0, sizeof(linux_sigset_t)))
		return TEST_RESULT_OTHER_FAILURE;

	linux_sigset_t set;
	linux_sigfillset(&set);

	if (linux_rt_sigprocmask(linux_SIG_BLOCK, &set, 0, sizeof(linux_sigset_t)))
		return TEST_RESULT_OTHER_FAILURE;

	linux_pid_t pid;
	if (linux_getpid(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_kill(pid, linux_SIGUSR1))
		return TEST_RESULT_OTHER_FAILURE;

	linux_sigdelset(&set, linux_SIGUSR1);
	if (linux_rt_sigsuspend(&set, sizeof(linux_sigset_t)) != linux_EINTR)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing rt_sigsuspend.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing rt_sigsuspend.\n");

	return ret;
}
