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

static char const filename[] = "some file";

static enum TestResult test_invalid_fd(void)
{
	linux_fd_t wd;
	if (linux_inotify_add_watch(linux_stderr + 1, filename, linux_IN_ALL_EVENTS, &wd) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd;
	if (linux_open(filename, linux_O_CREAT | linux_O_CLOEXEC, 0666, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_close(fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_inotify_init1(linux_IN_CLOEXEC, &fd))
	{
		linux_unlink(filename);
		return TEST_RESULT_OTHER_FAILURE;
	}

	linux_fd_t wd;
	if (linux_inotify_add_watch(fd, filename, linux_IN_ALL_EVENTS, &wd))
		return TEST_RESULT_FAILURE;

	linux_unlink(filename);
	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing inotify_add_watch.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing inotify_add_watch.\n");

	return ret;
}
