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

#include <string.h>
#include <stdatomic.h>

static bool futex_wait(uint32_t* futex)
{
	while (1)
	{
		if (__sync_bool_compare_and_swap(futex, 1, 0))
			break;

		enum linux_error_t const err = linux_futex(futex, linux_FUTEX_WAIT, 0, 0, 0, 0);
		if (err && (err != linux_EAGAIN))
			return false;
	}
	return true;
}

static bool futex_post(uint32_t* futex)
{
	if (__sync_bool_compare_and_swap(futex, 0, 1))
	{
		if (linux_futex(futex, linux_FUTEX_WAKE, 1, 0, 0, 0))
			return false;
	}
	return true;
}

static enum TestResult test_correct_usage(void)
{
	size_t const size = sizeof(uint32_t) * 2;
	void* mem;
	if (linux_mmap(0, size, linux_PROT_READ | linux_PROT_WRITE, linux_MAP_ANONYMOUS | linux_MAP_SHARED, 0, 0, &mem))
		return TEST_RESULT_OTHER_FAILURE;

	uint32_t* futex1 = (uint32_t*)mem + 0;
	uint32_t* futex2 = (uint32_t*)mem + 1;

	*futex1 = 0; // Unavailable
	*futex2 = 1; // Available

	linux_fd_t pipe[2];
	if (linux_pipe(pipe))
	{
		linux_munmap(mem, size);
		return TEST_RESULT_OTHER_FAILURE;
	}

	linux_pid_t pid;
	if (linux_fork(&pid))
	{
		linux_close(pipe[0]);
		linux_close(pipe[1]);
		linux_munmap(mem, size);
		return TEST_RESULT_OTHER_FAILURE;
	}

#define loops 100
	char correct_data[loops * 2];
	for (int i = 0; i < loops * 2; i += 2)
	{
		correct_data[i + 0] = 'p';
		correct_data[i + 1] = 'c';
	}

	if (!pid) // Child
	{
		if (linux_close(pipe[0]))
			linux_exit(2);

		for (int i = 0; i < loops; ++i)
		{
			if (!futex_wait(futex1))
				linux_exit(1);

			if (linux_write(pipe[1], "c", 1, 0))
				linux_exit(2);

			if (!futex_post(futex2))
				linux_exit(1);
		}
		linux_exit(0);
	}

	// Parent
	for (int i = 0; i < loops; ++i)
	{
		if (!futex_wait(futex2))
			return TEST_RESULT_FAILURE;

		if (linux_write(pipe[1], "p", 1, 0))
			return TEST_RESULT_OTHER_FAILURE;

		if (!futex_post(futex1))
			return TEST_RESULT_FAILURE;
	}
#undef loops

	int status;
	if (linux_wait4((linux_pid_t)-1, &status, 0, 0, 0))
	{
		linux_munmap(mem, size);
		return TEST_RESULT_OTHER_FAILURE;
	}

	char buf[512];
	size_t bytes_read;
	if (linux_read(pipe[0], buf, sizeof buf, &bytes_read))
		return TEST_RESULT_OTHER_FAILURE;

	if (memcmp(buf, correct_data, bytes_read))
		return TEST_RESULT_FAILURE;

	if (!linux_WIFEXITED(status))
		return TEST_RESULT_OTHER_FAILURE;

	enum TestResult ret = TEST_RESULT_SUCCESS;
	switch (linux_WEXITSTATUS(status))
	{
		case 1: ret = TEST_RESULT_FAILURE; break;
		case 2: ret = TEST_RESULT_OTHER_FAILURE; break;
	}

	linux_munmap(mem, size);
	return ret;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing futex.\n");
	DO_TEST(correct_usage, &ret);
	printf("Finished testing futex.\n");

	return ret;
}
