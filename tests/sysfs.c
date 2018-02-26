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
	if (linux_sysfs(2, 0, 0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_option(void)
{
	if (linux_sysfs(0, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;
	if (linux_sysfs(4, 0, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_fs_id(void)
{
	int num;
	if (linux_sysfs(3, 0, 0, &num) || num < 0)
		return TEST_RESULT_OTHER_FAILURE;

	char buf[512];
	if (linux_sysfs(2, (unsigned)num, (uintptr_t)buf, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;
	if (linux_sysfs(2, (uintptr_t)-1, (uintptr_t)buf, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	int num;
	if (linux_sysfs(3, 0, 0, &num) || num < 0)
		return TEST_RESULT_FAILURE;

	for (int i = 0; i < num; ++i)
	{
		char buf[512];
		if (linux_sysfs(2, (unsigned)i, (uintptr_t)buf, 0))
			return TEST_RESULT_FAILURE;
	}

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing sysfs.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_option, &ret);
	DO_TEST(invalid_fs_id, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing sysfs.\n");

	return ret;
}
