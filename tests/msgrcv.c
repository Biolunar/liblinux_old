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

static enum TestResult test_segfault(void)
{
	linux_msgid_t id = 0;
	if  (linux_msgget(linux_IPC_PRIVATE, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_msgbuf_t const buf =
	{
		.mtype = 42,
	};
	if (linux_msgsnd(id, &buf, 0, linux_IPC_NOWAIT))
	{
		linux_msgctl(id, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_OTHER_FAILURE;
	}

	if (linux_msgrcv(id, 0, 1, 0, linux_IPC_NOWAIT, 0) != linux_EFAULT)
	{
		linux_msgctl(id, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	linux_msgctl(id, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_id(void)
{
	struct linux_msgbuf_t buf =
	{
		.mtype = 42,
	};
	if (linux_msgrcv(-1, &buf, 0, 0, linux_IPC_NOWAIT, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	enum TestResult result = TEST_RESULT_SUCCESS;

	linux_msgid_t id = 0;
	struct linux_msgbuf_t* buf = 0;
	struct linux_msgbuf_t* recv_buf = 0;

	if  (linux_msgget(linux_IPC_PRIVATE, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
	{
		result = TEST_RESULT_OTHER_FAILURE;
		goto out;
	}

	char const msg[] = "Hello world!";
	buf = malloc(sizeof *buf + sizeof msg);
	if (!buf)
	{
		result = TEST_RESULT_OTHER_FAILURE;
		goto out;
	}

	buf->mtype = 42;
	memcpy(buf->mtext, msg, sizeof msg);
	if (linux_msgsnd(id, buf, sizeof msg, linux_IPC_NOWAIT))
	{
		result = TEST_RESULT_OTHER_FAILURE;
		goto out;
	}

	size_t const recv_size = 256;
	recv_buf = malloc(sizeof *recv_buf + recv_size);
	if (!buf)
	{
		result = TEST_RESULT_OTHER_FAILURE;
		goto out;
	}

	size_t ret;
	if (linux_msgrcv(id, recv_buf, recv_size, 0, linux_IPC_NOWAIT, &ret) || ret != sizeof msg)
	{
		result = TEST_RESULT_FAILURE;
		goto out;
	}

out:
	free(recv_buf);
	free(buf);
	if (id != 0)
		linux_msgctl(id, linux_IPC_RMID, 0, 0);
	return result;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing msgrcv.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_id, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing msgrcv.\n");

	return ret;
}
