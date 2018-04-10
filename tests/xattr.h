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

#ifndef HEADER_LIBLINUX_TESTS_XATTR_H_INCLUDED
#define HEADER_LIBLINUX_TESTS_XATTR_H_INCLUDED

#include <liblinux/linux.h>

#include <assert.h>

struct File
{
	char const* name;
	linux_fd_t fd;
	char _pad[4];
};

static void file_close(struct File* const f)
{
	assert(f);
	linux_close(f->fd);
	linux_unlink(f->name);
}

static enum TestResult file_create(struct File* const f)
{
	assert(f);

	f->name = "/tmp/liblinux_testfile";
	if (linux_open(f->name, linux_O_RDWR | linux_O_CREAT, 0666, &f->fd))
		return TEST_RESULT_OTHER_FAILURE;

	char const data[] = "test data";
	enum linux_error_t err = linux_setxattr(f->name, "user.liblinux", data, sizeof data, linux_XATTR_CREATE);
	if (err && err == linux_EOPNOTSUPP)
	{
		file_close(f);

		f->name = "liblinux_testfile";
		if (linux_open(f->name, linux_O_RDWR | linux_O_CREAT, 0666, &f->fd))
			return TEST_RESULT_OTHER_FAILURE;

		if (linux_setxattr(f->name, "user.liblinux", data, sizeof data, linux_XATTR_CREATE))
		{
			file_close(f);
			return TEST_RESULT_FAILURE;
		}
	}
	else if (err)
	{
		file_close(f);
		return TEST_RESULT_FAILURE;
	}

	return TEST_RESULT_SUCCESS;
}

#endif // !HEADER_LIBLINUX_TESTS_XATTR_H_INCLUDED
