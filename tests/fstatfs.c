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
	linux_fd_t fd;
	if (linux_open("/proc/self/maps", linux_O_RDONLY, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_fstatfs(fd, 0) != linux_EFAULT)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd;
	if (linux_open("/proc/self/maps", linux_O_RDONLY, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_statfs_t ret;
	if (linux_fstatfs(fd, &ret))
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing fstatfs.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing fstatfs.\n");

	return ret;
}
