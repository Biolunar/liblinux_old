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

static enum TestResult test_invalid_fd(void)
{
	struct linux_itimerspec_t const new =
	{
		.it_value = { .tv_nsec = 100, },
	};

	struct linux_itimerspec_t old;
	if (linux_timerfd_settime(linux_stderr + 1, 0, &new, &old) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_sigset_t set;
	linux_sigemptyset(&set);

	linux_fd_t fd;
	if (linux_timerfd_create(linux_CLOCK_REALTIME, linux_TFD_CLOEXEC, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_itimerspec_t const new =
	{
		.it_value = { .tv_nsec = 100, },
	};
	struct linux_itimerspec_t old;
	if (linux_timerfd_settime(fd, 0, &new, &old))
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

	printf("Start testing timerfd_settime.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing timerfd_settime.\n");

	return ret;
}
