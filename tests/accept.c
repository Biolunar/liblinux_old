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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

static uint16_t const port = 6112;
static uint32_t const ip = 0x0100007F; // 127.0.0.1 == 0x7F000001

static enum TestResult test_invalid_fd(void)
{
	if (linux_accept(linux_stderr + 1, 0, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static void* connect_thread(void* const param)
{
	struct sockaddr_in* sa = param;

	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return (void*)EXIT_FAILURE;

	if (connect((int)fd, (struct sockaddr*)sa, sizeof *sa))
		return (void*)EXIT_FAILURE;

	linux_close(fd);
	return (void*)EXIT_SUCCESS;
}

static enum TestResult test_segfault(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (setsockopt((int)fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	struct sockaddr_in sa =
	{
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = ip,
		},
	};

	if (bind((int)fd, (struct sockaddr const*)&sa, sizeof sa) == -1)
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (listen((int)fd, 10) == -1)
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	pthread_t child;
	if (pthread_create(&child, 0, &connect_thread, &sa))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_accept(fd, (struct linux_sockaddr_t*)1, 0, 0) != linux_EFAULT)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	void* ret = 0;
	if (pthread_join(child, &ret))
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}
	if ((int)ret != EXIT_SUCCESS)
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_non_listening(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (setsockopt((int)fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	struct sockaddr_in sa =
	{
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = ip,
		},
	};

	if (bind((int)fd, (struct sockaddr const*)&sa, sizeof sa) == -1)
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (linux_accept(fd, (struct linux_sockaddr_t*)1, 0, 0) != linux_EINVAL)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
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
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (setsockopt((int)fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1)
		return TEST_RESULT_OTHER_FAILURE;

	struct sockaddr_in sa =
	{
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = ip,
		},
	};

	if (bind((int)fd, (struct sockaddr const*)&sa, sizeof sa) == -1)
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (listen((int)fd, 10) == -1)
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	pthread_t child;
	if (pthread_create(&child, 0, &connect_thread, &sa))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sockaddr_in_t csa;
	memset(&csa, 0, sizeof csa);
	int len = 0;
	if (linux_accept(fd, (struct linux_sockaddr_t*)&csa, &len, 0))
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	void* ret = 0;
	if (pthread_join(child, &ret))
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}
	if ((int)ret != EXIT_SUCCESS)
	{
		linux_close(fd);
		return TEST_RESULT_OTHER_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing accept.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(non_listening, &ret);
	DO_TEST(fd_not_socket, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing accept.\n");

	return ret;
}
