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

static enum TestResult test_correct_usage(void)
{
	struct linux_perf_event_attr_t attr =
	{
		.type = linux_PERF_TYPE_HARDWARE,
		.size = sizeof(struct linux_perf_event_attr_t),
		.config = linux_PERF_COUNT_HW_INSTRUCTIONS,
		.disabled = 1,
		.exclude_kernel = 1,
		.exclude_hv = 1,
	};

	linux_fd_t fd;
	if (linux_perf_event_open(&attr, 0, -1, (linux_fd_t)-1, linux_PERF_FLAG_FD_CLOEXEC, &fd))
		return TEST_RESULT_FAILURE;

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing perf_event_open.\n");
	DO_TEST(correct_usage, &ret);
	printf("Finished testing perf_event_open.\n");

	return ret;
}
