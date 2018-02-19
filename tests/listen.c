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

#include <stdint.h>
#include <arpa/inet.h>

static uint16_t const port = 6112;

static enum TestResult test_invalid_fd(void)
{
	if (linux_accept(linux_stderr + 1, 0, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_fd_not_socket(void)
{
	if (linux_accept(linux_stdout, 0, 0, 0) != linux_ENOTSOCK)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;

	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		goto error;

	if (setsockopt((int)fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
		goto error_fd;

	struct linux_sockaddr_in_t sa =
	{
		.sin_family = linux_AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = htonl(linux_INADDR_LOOPBACK),
		},
	};

	if (linux_bind(fd, (struct linux_sockaddr_t const*)&sa, sizeof sa))
		goto error_fd;

	if (linux_listen(fd, 1))
	{
		ret = TEST_RESULT_FAILURE;
		goto error_fd;
	}

	ret = TEST_RESULT_SUCCESS;
error_fd:
	linux_close(fd);
error:
	return ret;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing listen.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(fd_not_socket, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing listen.\n");

	return ret;
}
