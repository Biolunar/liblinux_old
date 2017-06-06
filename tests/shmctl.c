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

static enum TestResult test_invalid_buf(void)
{
	int id = 1234;
	if (linux_shmget(linux_IPC_PRIVATE, linux_SHMMIN, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_shmctl(id, linux_IPC_SET, 0, 0) != linux_EFAULT)
	{
		linux_shmctl(id, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	linux_shmctl(id, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_id(void)
{
	int id = 1234;
	if (linux_shmget(linux_IPC_PRIVATE, linux_SHMMIN, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_shmctl(id, linux_IPC_RMID, 0, 0))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_shmid64_ds buf;
	memset(&buf, 0, sizeof buf);
	if (linux_shmctl(id, linux_IPC_STAT, &buf, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_remove(void)
{
	int id = 1234;
	if (linux_shmget(linux_IPC_PRIVATE, linux_SHMMIN, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	int index = 1234;
	if (linux_shmctl(id, linux_IPC_RMID, 0, &index) || index != 0)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_get_info(void)
{
	int id = 1234;
	if (linux_shmget(linux_IPC_PRIVATE, linux_SHMMIN, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	int index;

	struct linux_shmid64_ds buf1;
	memset(&buf1, 0xFF, sizeof buf1);
	index = 1234;
	if (linux_shmctl(id, linux_IPC_STAT, &buf1, &index) || index != 0)
	{
		linux_shmctl(id, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	struct linux_shminfo64 buf2;
	memset(&buf2, 0xFF, sizeof buf2);
	index = 0;
	if (linux_shmctl(id, linux_IPC_INFO, (struct linux_shmid64_ds*)&buf2, &index) || index == 0)
	{
		linux_shmctl(id, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	struct linux_shm_info buf3;
	memset(&buf3, 0xFF, sizeof buf3);
	index = 0;
	if (linux_shmctl(id, linux_SHM_INFO, (struct linux_shmid64_ds*)&buf3, &index) || index == 0)
	{
		linux_shmctl(id, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	linux_shmctl(id, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing shmctl.\n");
	DO_TEST(invalid_buf, &ret);
	DO_TEST(invalid_id, &ret);
	DO_TEST(remove, &ret);
	DO_TEST(get_info, &ret);
	printf("Finished testing shmctl.\n");

	return ret;
}
