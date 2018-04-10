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

enum
{
	BUFFER_SIZE = 512,
};

static enum TestResult test_invalid_fd(void)
{
	int const data = 42;
	size_t ret;
	if (linux_write(linux_stderr + 1, &data, sizeof data, &ret) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_buf(void)
{
	// Cannot use /dev/null, because every write to it is successful.
	linux_fd_t fd;
	if (linux_open("/tmp", linux_O_WRONLY | linux_O_TMPFILE, 0666, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_write((linux_fd_t)fd, 0, BUFFER_SIZE, 0) != linux_EFAULT)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_write_zero(void)
{
	linux_fd_t fd;
	// Cannot use /dev/null, because every write to it is successful.
	if (linux_open("/tmp", linux_O_WRONLY | linux_O_TMPFILE, 0666, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	int const data = 42;
	size_t ret = 0;
	if (linux_write((linux_fd_t)fd, &data, 0, &ret) || ret > 0)
	{
		linux_close(fd);
		return TEST_RESULT_FAILURE;
	}

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

static size_t read_all(linux_fd_t const fd, void* buf, size_t count)
{
	char* const b = buf;
	size_t bytes_read = 0;
	while (bytes_read < count)
	{
		size_t ret;
		if (linux_read(fd, b + bytes_read, count - bytes_read, &ret) || !ret)
			return bytes_read;
		bytes_read += ret;
	}
	return bytes_read;
}

static enum TestResult test_random_write(void)
{
	linux_fd_t fd;
	if (linux_open("/dev/urandom", linux_O_RDONLY, 0, &fd))
		return TEST_RESULT_OTHER_FAILURE;

	char in_buf[BUFFER_SIZE];
	size_t bytes_read = read_all(fd, in_buf, sizeof in_buf);
	if (bytes_read != sizeof in_buf)
		return TEST_RESULT_OTHER_FAILURE;
	linux_close(fd);

	linux_fd_t pfd[2] = {(linux_fd_t)-1, (linux_fd_t)-1};
	if (linux_pipe(pfd))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_write(pfd[1], in_buf, sizeof in_buf, 0))
	{
		linux_close(pfd[0]);
		linux_close(pfd[1]);
		return TEST_RESULT_FAILURE;
	}

	char out_buf[sizeof in_buf];
	bytes_read = read_all(pfd[0], out_buf, sizeof out_buf);
	if (bytes_read != sizeof out_buf)
	{
		linux_close(pfd[0]);
		linux_close(pfd[1]);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (memcmp(out_buf, in_buf, sizeof out_buf))
	{
		linux_close(pfd[0]);
		linux_close(pfd[1]);
		return TEST_RESULT_FAILURE;
	}

	linux_close(pfd[0]);
	linux_close(pfd[1]);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing write.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_buf, &ret);
	DO_TEST(write_zero, &ret);
	DO_TEST(random_write, &ret);
	printf("Finished testing write.\n");

	return ret;
}
