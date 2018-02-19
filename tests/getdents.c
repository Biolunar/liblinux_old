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
#include <stdalign.h>

static enum TestResult test_invalid_fd(void)
{
	char buf[512];
	if  (linux_getdents(linux_stderr + 1, (void*)buf, sizeof buf, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_segfault(void)
{
	linux_fd_t fd;
	if (linux_open(".", linux_O_RDONLY | linux_O_CLOEXEC | linux_O_DIRECTORY, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if  (linux_getdents(fd, 0, 512, 0) != linux_EFAULT)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_size(void)
{
	linux_fd_t fd;
	if (linux_open(".", linux_O_RDONLY | linux_O_CLOEXEC | linux_O_DIRECTORY, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	alignas(struct linux_dirent_t)char buf[1];
	if  (linux_getdents(fd, (struct linux_dirent_t*)buf, sizeof buf, 0) != linux_EINVAL)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_not_directory(void)
{
	alignas(struct linux_dirent_t)char buf[512];
	if  (linux_getdents(linux_stdout, (struct linux_dirent_t*)buf, sizeof buf, 0) != linux_ENOTDIR)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd;
	if (linux_open(".", linux_O_RDONLY | linux_O_CLOEXEC | linux_O_DIRECTORY, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	alignas(struct linux_dirent_t) char buf[linux_NAME_MAX];
	memset(buf, 0, sizeof buf);

	while (1)
	{
		unsigned int ret = 0;
		if  (linux_getdents(fd, (struct linux_dirent_t*)buf, sizeof buf, &ret))
		{
			linux_close(fd);
			return TEST_RESULT_FAILURE;
		}

		if (ret == 0)
			break;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing getdents.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_size, &ret);
	DO_TEST(not_directory, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing getdents.\n");

	return ret;
}
