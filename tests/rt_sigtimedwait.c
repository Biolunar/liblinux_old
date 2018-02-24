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

static enum TestResult test_invalid_timeout(void)
{
	linux_sigset_t set;
	linux_sigemptyset(&set);

	struct linux_timespec_t const ts =
	{
		.tv_sec = -1,
		.tv_nsec = -1,
	};

	int ret;
	if (linux_rt_sigtimedwait(&set, 0, &ts, sizeof(linux_sigset_t), &ret) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_sigset_t set;
	linux_sigemptyset(&set);
	linux_sigaddset(&set, linux_SIGUSR1);

	linux_sigset_t old_set;
	if (linux_rt_sigprocmask(linux_SIG_BLOCK, &set, &old_set, sizeof(linux_sigset_t)))
		return TEST_RESULT_OTHER_FAILURE;

	linux_pid_t pid;
	if (linux_getpid(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_kill(pid, linux_SIGUSR1))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_siginfo_t info;
	struct linux_timespec_t const ts =
	{
		.tv_sec = 0,
		.tv_nsec = 0,
	};

	int ret;
	if (linux_rt_sigtimedwait(&set, &info, &ts, sizeof(linux_sigset_t), &ret) || ret != linux_SIGUSR1)
		return TEST_RESULT_FAILURE;

	if (linux_rt_sigprocmask(linux_SIG_SETMASK, &old_set, 0, sizeof(linux_sigset_t)))
		return TEST_RESULT_OTHER_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing rt_sigtimedwait.\n");
	DO_TEST(invalid_timeout, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing rt_sigtimedwait.\n");

	return ret;
}
