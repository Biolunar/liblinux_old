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
#include <string.h>
#include <arpa/inet.h>

static uint16_t const port = 6112;

static enum TestResult test_invalid_fd(void)
{
	if (linux_getpeername(linux_stderr + 1, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_not_socket(void)
{
	if (linux_getpeername(linux_stderr, 0, 0) != linux_ENOTSOCK)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_segfault(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_DGRAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sockaddr_in_t const sa =
	{
		.sin_family = linux_AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = htonl(linux_INADDR_LOOPBACK),
		},
	};

	if (linux_connect(fd, (struct linux_sockaddr_t const*)&sa, sizeof sa))
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	int size = sizeof(struct linux_sockaddr_in_t);
	if (linux_getpeername(fd, 0, &size) != linux_EFAULT)
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
	if (linux_socket(linux_PF_INET, linux_SOCK_DGRAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sockaddr_in_t const sa =
	{
		.sin_family = linux_AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = htonl(linux_INADDR_LOOPBACK),
		},
	};

	if (linux_connect(fd, (struct linux_sockaddr_t const*)&sa, sizeof sa))
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	struct linux_sockaddr_in_t csa;
	memset(&csa, 0, sizeof csa);
	int csa_len = sizeof csa;
	if  (linux_getpeername(fd, (struct linux_sockaddr_t*)&csa, &csa_len) || memcmp(&sa, &csa, sizeof sa) || csa_len != sizeof csa)
		return TEST_RESULT_FAILURE;

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing getpeername.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(not_socket, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing getpeername.\n");

	return ret;
}
