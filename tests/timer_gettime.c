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

static enum TestResult test_segfault(void)
{
	linux_pid_t tid;
	if (linux_gettid(&tid))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sigevent_t event =
	{
		.sigev_notify = linux_SIGEV_NONE,
		.sigev_un.tid = tid,
	};
	linux_timer_t timer;
	if (linux_timer_create(linux_CLOCK_MONOTONIC, &event, &timer))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_timer_gettime(timer, (struct linux_itimerspec_t*)-1) != linux_EFAULT)
	{
		linux_timer_delete(timer);
		return TEST_RESULT_FAILURE;
	}

	linux_timer_delete(timer);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_id(void)
{
	struct linux_itimerspec_t value;
	if (linux_timer_gettime(0, &value) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_pid_t tid;
	if (linux_gettid(&tid))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sigevent_t event =
	{
		.sigev_notify = linux_SIGEV_NONE,
		.sigev_un.tid = tid,
	};
	linux_timer_t timer;
	if (linux_timer_create(linux_CLOCK_MONOTONIC, &event, &timer))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_itimerspec_t value;
	if (linux_timer_gettime(timer, &value))
	{
		linux_timer_delete(timer);
		return TEST_RESULT_FAILURE;
	}

	linux_timer_delete(timer);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing timer_gettime.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_id, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing timer_gettime.\n");

	return ret;
}
