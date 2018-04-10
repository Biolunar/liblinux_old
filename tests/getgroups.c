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
	enum linux_error_t err = linux_EINVAL;
	while (err == linux_EINVAL)
	{
		int len;
		if (linux_getgroups(0, 0, &len) || len <= 0)
			return TEST_RESULT_FAILURE;

		int ret;
		err = linux_getgroups(len, 0, &ret);
		if (err == linux_EINVAL)
			continue;
		else if (err != linux_EFAULT)
			return TEST_RESULT_FAILURE;
	}

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_gid_t* list = 0;

	enum linux_error_t err = linux_EINVAL;
	while (err == linux_EINVAL)
	{
		int len;
		if (linux_getgroups(0, 0, &len) || len < 0)
		{
			free(list);
			return TEST_RESULT_FAILURE;
		}

		linux_gid_t* const new_list = realloc(list, (unsigned)len * sizeof(linux_gid_t));
		if (!new_list)
		{
			free(list);
			return TEST_RESULT_OTHER_FAILURE;
		}
		list = new_list;

		int ret;
		err = linux_getgroups(len, list, &ret);
		if ((err && err != linux_EINVAL) || ret < 0)
		{
			free(list);
			return TEST_RESULT_FAILURE;
		}
	}

	free(list);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing getgroups.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing getgroups.\n");

	return ret;
}
