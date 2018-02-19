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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define BUFFER_SIZE 512

static enum TestResult test_invalid_fd(void)
{
	char buf[BUFFER_SIZE] = {0};
	struct linux_iovec_t vec =
	{
		.iov_base = buf,
		.iov_len = sizeof buf,
	};
	if (linux_writev(linux_stderr + 1, &vec, 1, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_buf(void)
{
	// Cannot use /dev/null, because every write to it is successful.
	int const fd = open(".", O_WRONLY | 020000000 | 00200000, S_IWUSR); // TODO: Use O_TMPFILE instead of 020000000 | 00200000
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_iovec_t vec =
	{
		.iov_base = 0,
		.iov_len = BUFFER_SIZE,
	};
	if (linux_writev((linux_fd_t)fd, &vec, 1, 0) != linux_EFAULT)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_write_zero(void)
{
	int const fd = open("/dev/null", O_WRONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	char buf[1] = {0};
	struct linux_iovec_t vec =
	{
		.iov_base = buf,
		.iov_len = 0,
	};
	size_t result = 0;
	if (linux_writev((linux_fd_t)fd, &vec, 1, &result) || result)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_random_write(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;
	int p[2] = {-1, -1};
	FILE* file = 0;

	if (pipe(p) == -1)
		goto cleanup;

	if (p[0] == -1 || p[1] == -1)
		goto cleanup;

	file = fopen("/dev/urandom", "r");
	if (!file)
		goto cleanup;

	char in_buf[BUFFER_SIZE] = {0};
	if (fread(in_buf, 1, sizeof in_buf, file) != sizeof in_buf)
		goto cleanup;

	struct linux_iovec_t vec =
	{
		.iov_base = in_buf,
		.iov_len = sizeof in_buf,
	};
	if (linux_writev((linux_fd_t)p[1], &vec, 1, 0))
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	char out_buf[sizeof in_buf] = {0};
	size_t to_read = sizeof out_buf;
	while (to_read)
	{
		ssize_t const bytes_read = read(p[0], out_buf + (sizeof out_buf - to_read), to_read);
		if (bytes_read < 0)
			goto cleanup;
		to_read -= (size_t)bytes_read;
	}

	if (memcmp(out_buf, in_buf, sizeof out_buf))
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	ret = TEST_RESULT_SUCCESS;

cleanup:
	if (file)
		fclose(file);
	if (p[0] != -1)
		close(p[0]);
	if (p[1] != -1)
		close(p[1]);
	return ret;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing writev.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_buf, &ret);
	DO_TEST(write_zero, &ret);
	DO_TEST(random_write, &ret);
	printf("Finished testing writev.\n");

	return ret;
}
