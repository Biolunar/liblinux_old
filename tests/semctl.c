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

static enum TestResult test_invalid_arg(void)
{
	linux_semid_t id = 0;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_semctl(id, 0, linux_IPC_SET, 0, 0) != linux_EFAULT)
	{
		linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_id(void)
{
	union linux_semun_t arg =
	{
		.val = 0,
	};
	if (linux_semctl(-1, 0, linux_SETVAL, (unsigned long)&arg, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_remove(void)
{
	linux_semid_t id = 0;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_semctl(id, 0, linux_IPC_RMID, 0, 0))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_get_info(void)
{
	linux_semid_t id = 0;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	union linux_semun_t uarg;
	unsigned long arg;

	struct linux_semid64_ds_t buf1;
	memset(&buf1, 0, sizeof buf1);
	uarg.buf = &buf1;
	memcpy(&arg, &uarg, sizeof arg);
	if (linux_semctl(id, 0, linux_IPC_STAT, arg, 0))
	{
		linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	struct linux_seminfo_t buf2;
	memset(&buf2, 0, sizeof buf2);
	uarg.info = &buf2;
	memcpy(&arg, &uarg, sizeof arg);
	if (linux_semctl(id, 0, linux_IPC_INFO, arg, 0))
	{
		linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing semctl.\n");
	DO_TEST(invalid_arg, &ret);
	DO_TEST(invalid_id, &ret);
	DO_TEST(remove, &ret);
	DO_TEST(get_info, &ret);
	printf("Finished testing semctl.\n");

	return ret;
}
