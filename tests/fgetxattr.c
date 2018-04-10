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

#include "xattr.h"

static enum TestResult test_buffer_too_small(void)
{
	struct File f;
	if (file_create(&f))
		return TEST_RESULT_OTHER_FAILURE;

	char const data[] = "test data";
	if (linux_setxattr(f.name, "user.liblinux", data, sizeof data, 0))
	{
		file_close(&f);
		return TEST_RESULT_OTHER_FAILURE;
	}

	char buf[sizeof data - 1];
	size_t ret;
	if (linux_fgetxattr(f.fd, "user.liblinux", buf, sizeof buf, &ret) != linux_ERANGE)
	{
		file_close(&f);
		return TEST_RESULT_FAILURE;
	}

	file_close(&f);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	struct File f;
	if (file_create(&f))
		return TEST_RESULT_OTHER_FAILURE;

	char const data[] = "test data";
	if (linux_setxattr(f.name, "user.liblinux", data, sizeof data, 0))
	{
		file_close(&f);
		return TEST_RESULT_OTHER_FAILURE;
	}

	char buf[512];
	size_t ret;
	if (linux_fgetxattr(f.fd, "user.liblinux", buf, sizeof buf, &ret))
	{
		file_close(&f);
		return TEST_RESULT_FAILURE;
	}

	if (memcmp(buf, data, ret))
	{
		file_close(&f);
		return TEST_RESULT_FAILURE;
	}

	file_close(&f);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing fgetxattr.\n");
	DO_TEST(buffer_too_small, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing fgetxattr.\n");

	return ret;
}
