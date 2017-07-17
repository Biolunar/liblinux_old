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

static enum TestResult test_invalid_fd(void)
{
	if (linux_connect(linux_stderr + 1, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_segfault(void)
{
	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_connect(fd, 0, sizeof(struct linux_sockaddr_in_t)) != linux_EFAULT)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

// TODO: If this thread exits before it accepts incoming connections, the main thread will hang!
static void* listen_thread(void* const param)
{
	(void)param;
	void* ret = (void*)EXIT_FAILURE;

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

	struct linux_sockaddr_in_t csa;
	memset(&csa, 0, sizeof csa);
	int csa_len = sizeof csa;

	linux_fd_t con_fd;
	if (linux_accept(fd, (struct linux_sockaddr_t*)&csa, &csa_len, &con_fd))
		goto error_fd;

	ret = (void*)EXIT_SUCCESS;
	linux_close(con_fd);
error_fd:
	linux_close(fd);
error:
	return ret;
}

static enum TestResult test_correct_usage(void)
{
	pthread_t child;
	if (pthread_create(&child, 0, &listen_thread, 0))
		return TEST_RESULT_OTHER_FAILURE;

	linux_fd_t fd;
	if (linux_socket(linux_PF_INET, linux_SOCK_STREAM, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sockaddr_in_t sa =
	{
		.sin_family = linux_AF_INET,
		.sin_port = htons(port),
		.sin_addr =
		{
			.s_addr = htonl(linux_INADDR_LOOPBACK),
		},
	};

	enum linux_error_t err;
	while ((err = linux_connect(fd, (struct linux_sockaddr_t*)&sa, sizeof sa)) == linux_ECONNREFUSED)
		linux_sched_yield();
	if (err)
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

	printf("Start testing connect.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing connect.\n");

	return ret;
}
