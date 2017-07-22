/*
 * Copyright 2017 Mahdi Khanalizadeh
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
#include <arpa/inet.h>

static uint16_t const port = 6112;
static char message[] = "Hello world!";

static enum TestResult test_invalid_fd(void)
{
	char buf[] = {0};
	struct linux_iovec_t vec =
	{
		.iov_base = buf,
		.iov_len = sizeof buf,
	};
	struct linux_user_msghdr_t const msg =
	{
		.msg_iov = &vec,
		.msg_iovlen = 1,
	};

	if (linux_sendmsg(linux_stderr + 1, &msg, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_segfault(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_DGRAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sockaddr_in_t sa =
	{
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = linux_INADDR_LOOPBACK,
		},
	};

	struct linux_iovec_t vec =
	{
		.iov_base = 0,
		.iov_len = 1,
	};
	struct linux_user_msghdr_t const msg =
	{
		.msg_name = &sa,
		.msg_namelen = sizeof sa,
		.msg_iov = &vec,
		.msg_iovlen = 1,
	};

	if (linux_sendmsg(fd, &msg, 0, 0) != linux_EFAULT)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_no_dest_addr(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_DGRAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_iovec_t vec =
	{
		.iov_base = message,
		.iov_len = sizeof message,
	};
	struct linux_user_msghdr_t const msg =
	{
		.msg_iov = &vec,
		.msg_iovlen = 1,
	};

	if (linux_sendmsg(fd, &msg, 0, 0) != linux_EDESTADDRREQ)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_fd_not_socket(void)
{
	struct linux_iovec_t vec =
	{
		.iov_base = message,
		.iov_len = sizeof message,
	};
	struct linux_user_msghdr_t const msg =
	{
		.msg_iov = &vec,
		.msg_iovlen = 1,
	};

	if (linux_sendmsg(linux_stdout, &msg, 0, 0) != linux_ENOTSOCK)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_DGRAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sockaddr_in_t sa =
	{
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = linux_INADDR_LOOPBACK,
		},
	};
	struct linux_iovec_t vec =
	{
		.iov_base = message,
		.iov_len = sizeof message,
	};
	struct linux_user_msghdr_t const msg =
	{
		.msg_name = &sa,
		.msg_namelen = sizeof sa,
		.msg_iov = &vec,
		.msg_iovlen = 1,
	};

	size_t ret = 0;
	if (linux_sendmsg(fd, &msg, 0, &ret) || ret != sizeof message)
		return TEST_RESULT_FAILURE;

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing sendmsg.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(no_dest_addr, &ret);
	DO_TEST(fd_not_socket, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing sendmsg.\n");

	return ret;
}
