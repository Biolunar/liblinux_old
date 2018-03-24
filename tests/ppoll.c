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

#include <unistd.h>

static enum TestResult test_timeout(void)
{
	int p[2] = { -1, -1 };
	if (pipe(p) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_pollfd_t pfd =
	{
		.fd = p[1],
		.events = linux_POLLIN,
		.revents = 0,
	};
	struct linux_timespec_t ts =
	{
		.tv_sec = 0,
		.tv_nsec = 10000,
	};
	unsigned int ret = 0;
	if (linux_ppoll(&pfd, 1, &ts, 0, sizeof(linux_sigset_t), &ret) || ret != 0 || pfd.revents != 0)
	{
		close(p[0]);
		close(p[1]);
		return TEST_RESULT_FAILURE;
	}

	close(p[0]);
	close(p[1]);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing ppoll.\n");
	DO_TEST(timeout, &ret);
	printf("Finished testing ppoll.\n");

	return ret;
}
