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
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static uint16_t const port = 6112;
static char message[] = "Hello world!";

static enum TestResult test_invalid_fd(void)
{
	char buf[] = {0};
	if (linux_recvfrom(linux_stderr + 1, buf, sizeof buf, 0, 0, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static void* send_thread(void* const param)
{
	(void)param;

	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return (void*)EXIT_FAILURE;

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
		return (void*)EXIT_FAILURE;
	}

	if (linux_sendto(fd, message, sizeof message, 0, 0, 0, 0))
	{
		linux_close(fd);
		return (void*)EXIT_FAILURE;
	}

	return (void*)EXIT_SUCCESS;
}

static enum TestResult test_segfault(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;

	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		goto error;

	if (setsockopt((int)fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
		goto error_fd;

	struct sockaddr_in sa =
	{
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = htonl(INADDR_LOOPBACK),
		},
	};

	if (bind((int)fd, (struct sockaddr const*)&sa, sizeof sa) == -1)
		goto error_fd;

	if (listen((int)fd, 10) == -1)
		goto error_fd;

	pthread_t child;
	if (pthread_create(&child, 0, &send_thread, &sa))
		goto error_fd;

	linux_fd_t con_fd = 0;
	if (linux_accept(fd, 0, 0, &con_fd))
		goto error_fd;

	void* thread_ret = 0;
	if (pthread_join(child, &thread_ret) || (int)thread_ret != EXIT_SUCCESS)
		goto error_con_fd;

	if (linux_recvfrom(con_fd, 0, 1, 0, 0, 0, 0) != linux_EFAULT)
		ret = TEST_RESULT_FAILURE;

	ret = TEST_RESULT_SUCCESS;

error_con_fd:
	linux_close(con_fd);
error_fd:
	linux_close(fd);
error:
	return ret;
}

static enum TestResult test_not_connected(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sockaddr_in_t sa;
	memset(&sa, 0, sizeof sa);

	if (linux_recvfrom(fd, message, sizeof message, 0, 0, 0, 0) != linux_ENOTCONN)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_fd_not_socket(void)
{
	char buf = 0;
	if (linux_recvfrom(linux_stdout, &buf, 1, 0, 0, 0, 0) != linux_ENOTSOCK)
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

	struct sockaddr_in sa =
	{
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = htonl(INADDR_LOOPBACK),
		},
	};

	if (bind((int)fd, (struct sockaddr const*)&sa, sizeof sa) == -1)
		goto error_fd;

	if (listen((int)fd, 10) == -1)
		goto error_fd;

	pthread_t child;
	if (pthread_create(&child, 0, &send_thread, &sa))
		goto error_fd;

	linux_fd_t con_fd = 0;
	if (linux_accept(fd, 0, 0, &con_fd))
		goto error_fd;

	void* thread_ret = 0;
	if (pthread_join(child, &thread_ret) || (int)thread_ret != EXIT_SUCCESS)
		goto error_con_fd;

	struct linux_sockaddr_in_t csa;
	memset(&csa, 0, sizeof csa);
	int csa_len = sizeof csa;

	char buf[sizeof message];
	memset(buf, 0, sizeof buf);
	size_t size = 0;
	if (linux_recvfrom(con_fd, buf, sizeof buf, 0, (struct linux_sockaddr_t*)&csa, &csa_len, &size) || size != sizeof message || strncmp(message, buf, sizeof message))
		ret = TEST_RESULT_FAILURE;

	ret = TEST_RESULT_SUCCESS;

error_con_fd:
	linux_close(con_fd);
error_fd:
	linux_close(fd);
error:
	return ret;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing recvfrom.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(not_connected, &ret);
	DO_TEST(fd_not_socket, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing recvfrom.\n");

	return ret;
}
