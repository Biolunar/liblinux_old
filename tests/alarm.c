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

#include <stdbool.h>

static bool volatile alarm_triggered = false;

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
		.sa_restorer = linux_rt_sigreturn,
	};
	linux_sigemptyset(&sa.sa_mask);
	if (linux_rt_sigaction(linux_SIGALRM, &sa, 0, sizeof(linux_sigset_t)))
		return TEST_RESULT_OTHER_FAILURE;

	unsigned int ret = 1234;
	if (linux_alarm(0, &ret) || ret != 0)
		return TEST_RESULT_FAILURE;

	if (linux_alarm(1, 0))
		return TEST_RESULT_FAILURE;

	while (!alarm_triggered)
		linux_pause(); // Just sleep forever if the signal does not trigger.

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing alarm.\n");
	DO_TEST(correct_usage, &ret);
	printf("Finished testing alarm.\n");

	return ret;
}
