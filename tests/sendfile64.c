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

static enum TestResult test_invalid_fd(void)
{
	if (linux_sendfile64(linux_stdout, linux_stderr + 1, 0, sizeof(int), 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	linux_fd_t in;
	if (linux_open("/dev/zero", linux_O_RDONLY, 0, &in))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_sendfile64(linux_stdin, in, 0, sizeof(int), 0) != linux_EINVAL)
	{
		linux_close(in);
		return TEST_RESULT_FAILURE;
	}

	linux_close(in);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t rnd;
	if (linux_open("/dev/urandom", linux_O_RDONLY, 0, &rnd))
		return TEST_RESULT_OTHER_FAILURE;

	char buf[linux_PAGE_SIZE];
	size_t read = 0;
	while (read != sizeof buf)
	{
		size_t ret = 0;
		if (linux_read(rnd, buf, sizeof buf - read, &ret))
		{
			linux_close(rnd);
			return TEST_RESULT_OTHER_FAILURE;
		}
		read += ret;
	}

	linux_close(rnd);

	linux_fd_t tmp;
	if (linux_open("/tmp", linux_O_RDWR | linux_O_TMPFILE, linux_S_IRWXU, &tmp))
		return TEST_RESULT_OTHER_FAILURE;

	size_t written = 0;
	while (written != sizeof buf)
	{
		size_t ret = 0;
		if (linux_write(tmp, buf, sizeof buf - written, &ret))
		{
			linux_close(tmp);
			return TEST_RESULT_FAILURE;
		}
		written += ret;
	}

	if (linux_lseek(tmp, 0, linux_SEEK_SET, 0))
		return TEST_RESULT_OTHER_FAILURE;

	linux_fd_t out;
	if (linux_open("/dev/null", linux_O_WRONLY, 0, &out))
	{
		linux_close(tmp);
		return TEST_RESULT_OTHER_FAILURE;
	}

	size_t ret = 0;
	if (linux_sendfile64(out, tmp, 0, sizeof buf, &ret) || ret != sizeof buf)
	{
		linux_close(tmp);
		linux_close(out);
		return TEST_RESULT_FAILURE;
	}

	linux_close(tmp);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing sendfile64.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing sendfile64.\n");

	return ret;
}
