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

static enum TestResult test_segfault(void)
{
	struct linux_user_cap_data_struct_t data[2];
	memset(data, 0, sizeof data);
	if (linux_capset(0, data) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_pid(void)
{
	struct linux_user_cap_header_struct_t header =
	{
		.version = linux_LINUX_CAPABILITY_VERSION_3,
		.pid = (linux_pid_t)-1,
	};
	struct linux_user_cap_data_struct_t data[2];
	memset(data, 0, sizeof data);
	if (!linux_capget(&header, data))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct linux_user_cap_header_struct_t header =
	{
		.version = linux_LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct linux_user_cap_data_struct_t data[2];
	memset(data, 0, sizeof data);
	if (linux_capset(&header, data))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing capset.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_pid, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing capset.\n");

	return ret;
}
