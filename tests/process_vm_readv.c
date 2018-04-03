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

static enum TestResult test_segfault(void)
{
	linux_pid_t pid;
	if (linux_getpid(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_iovec_t const vec =
	{
		.iov_base = 0,
		.iov_len = linux_PAGE_SIZE,
	};
	size_t ret;
	if (linux_process_vm_readv(pid, &vec, 1, &vec, 1, 0, &ret) != linux_EFAULT)
		return TEST_RESULT_FAILURE;
	if (linux_process_vm_readv(pid, 0, 1, &vec, 1, 0, &ret) != linux_EFAULT)
		return TEST_RESULT_FAILURE;
	if (linux_process_vm_readv(pid, &vec, 1, 0, 1, 0, &ret) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_pid_t pid;
	if (linux_getpid(&pid))
		return TEST_RESULT_OTHER_FAILURE;

	int src = 42;
	int dest = 0;

	struct linux_iovec_t const local =
	{
		.iov_base = &dest,
		.iov_len = sizeof dest,
	};
	struct linux_iovec_t const remote =
	{
		.iov_base = &src,
		.iov_len = sizeof src,
	};
	size_t ret;
	if (linux_process_vm_readv(pid, &local, 1, &remote, 1, 0, &ret) || ret != sizeof src || dest != src)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing process_vm_readv.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing process_vm_readv.\n");

	return ret;
}
