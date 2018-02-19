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

static char const* const newname = "some non existant filename";

static enum TestResult test_segfault(void)
{
	if (linux_symlink("oldname", newname))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_readlink(newname, 0, 1, 0) != linux_EFAULT)
	{
		linux_unlink(newname);
		return TEST_RESULT_FAILURE;
	}

	linux_unlink(newname);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_size(void)
{
	if (linux_symlink("oldname", newname))
		return TEST_RESULT_OTHER_FAILURE;

	char buf[linux_PATH_MAX];
	if (linux_readlink(newname, buf, -1, 0) != linux_EINVAL)
	{
		linux_unlink(newname);
		return TEST_RESULT_FAILURE;
	}

	linux_unlink(newname);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_no_entry(void)
{
	char buf[linux_PATH_MAX];
	if (linux_readlink(newname, buf, sizeof buf, 0) != linux_ENOENT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	if (linux_symlink("oldname", newname))
		return TEST_RESULT_OTHER_FAILURE;

	char buf[linux_PATH_MAX];
	if (linux_readlink(newname, buf, sizeof buf, 0))
	{
		linux_unlink(newname);
		return TEST_RESULT_FAILURE;
	}

	linux_unlink(newname);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing readlink.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_size, &ret);
	DO_TEST(no_entry, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing readlink.\n");

	return ret;
}
