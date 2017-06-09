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

#include <string.h>

static enum TestResult test_invalid_pointer(void)
{
	if (linux_nanosleep(0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_time(void)
{
	struct linux_timespec_t req;

	memset(&req, 0, sizeof req);
	req.tv_sec = -1;
	if (linux_nanosleep(&req, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	memset(&req, 0, sizeof req);
	req.tv_nsec = -1;
	if (linux_nanosleep(&req, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_timespec_t req =
	{
		.tv_sec = 0,
		.tv_nsec = 0,
	};
	struct linux_timespec_t rem;
	enum linux_error_t const err = linux_nanosleep(&req, &rem);
	if (err && err != linux_EINTR)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing nanosleep.\n");
	DO_TEST(invalid_pointer, &ret);
	DO_TEST(invalid_time, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing nanosleep.\n");

	return ret;
}
