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

#include <stdbool.h>
#include <string.h>

static bool volatile alarm_triggered = false;

static enum TestResult test_invalid_value(void)
{
	struct linux_itimerval_t value;
	memset(&value, 0, sizeof value);
	value.it_value.tv_usec = -1;
	if (linux_setitimer(linux_ITIMER_REAL, &value, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static void handler(int sig)
{
	(void)sig;

	alarm_triggered = true;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_sigaction_t sa =
	{
		.sa_handler = &handler,
		.sa_flags = linux_SA_RESTORER,
		.sa_restorer = &linux_rt_sigreturn,
	};
	linux_sigemptyset(&sa.sa_mask);
	if (linux_rt_sigaction(linux_SIGALRM, &sa, 0, sizeof(linux_sigset_t)))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_itimerval_t value =
	{
		.it_interval =
		{
			.tv_sec = 0,
			.tv_usec = 0,
		},
		.it_value =
		{
			.tv_sec = 0,
			.tv_usec = 1,
		},
	};
	struct linux_itimerval_t ovalue;
	if (linux_setitimer(linux_ITIMER_REAL, &value, &ovalue))
		return TEST_RESULT_FAILURE;

	while (!alarm_triggered)
		linux_pause(); // Leave the process sleeping if the signal does not trigger.

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing setitimer.\n");
	DO_TEST(invalid_value, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing setitimer.\n");

	return ret;
}
