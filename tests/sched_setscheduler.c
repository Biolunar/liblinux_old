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
	struct linux_sched_param_t const param = { .sched_priority = 0 };
	if (linux_sched_setscheduler((linux_pid_t)-1, linux_SCHED_NORMAL, &param) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_param(void)
{
	if (linux_sched_setscheduler(0, linux_SCHED_NORMAL, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_policy(void)
{
	struct linux_sched_param_t const param = { .sched_priority = 0 };

	if (linux_sched_setscheduler(0, linux_SCHED_NORMAL - 1, &param) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	if (linux_sched_setscheduler(0, linux_SCHED_DEADLINE + 1, &param) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_sched_param_t const param = { .sched_priority = 0 };
	if (linux_sched_setscheduler(0, linux_SCHED_NORMAL, &param))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing sched_setscheduler.\n");
	DO_TEST(invalid_pid, &ret);
	DO_TEST(invalid_param, &ret);
	DO_TEST(invalid_policy, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing sched_setscheduler.\n");

	return ret;
}
