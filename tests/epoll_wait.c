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

static enum TestResult test_invalid_flag(void)
{
	linux_fd_t fd;
	if (linux_epoll_create1(~linux_EPOLL_CLOEXEC, &fd) != linux_EINVAL)
		return TEST_RESULT_OTHER_FAILURE;

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd;
	if (linux_epoll_create1(linux_EPOLL_CLOEXEC, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	linux_fd_t pfd[2];
	if (linux_pipe(pfd))
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	struct linux_epoll_event_t event = { .events = linux_EPOLLIN };
	if (linux_epoll_ctl(fd, linux_EPOLL_CTL_ADD, pfd[0], &event))
	{
		linux_close(pfd[0]);
		linux_close(pfd[1]);
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	char const data[] = "some test data";
	if (linux_write(pfd[1], data, sizeof data, 0))
	{
		linux_close(pfd[0]);
		linux_close(pfd[1]);
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (linux_epoll_wait(fd, &event, 1, -1))
	{
		linux_close(pfd[0]);
		linux_close(pfd[1]);
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(pfd[0]);
	linux_close(pfd[1]);
	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing epoll_wait.\n");
	DO_TEST(invalid_flag, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing epoll_wait.\n");

	return ret;
}
