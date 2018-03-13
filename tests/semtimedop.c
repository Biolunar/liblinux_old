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

static enum TestResult test_no_access(void)
{
	linux_semid_t id;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL, &id))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sembuf_t sembuf =
	{
		.sem_num = 0,
		.sem_op = 1,
		.sem_flg = 0,
	};
	if (linux_semtimedop(id, &sembuf, 1, 0) != linux_EACCES)
	{
		linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_segfault(void)
{
	linux_semid_t id;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | 0666, &id))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sembuf_t sembuf =
	{
		.sem_num = 0,
		.sem_op = 1,
		.sem_flg = 0,
	};
	if (linux_semtimedop(id, &sembuf, 1, (struct linux_timespec_t*)-1) != linux_EFAULT)
	{
		linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}
	if (linux_semtimedop(id, 0, 1, 0) != linux_EFAULT)
	{
		linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_too_many(void)
{
	linux_semid_t id;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | 0666, &id))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sembuf_t sembuf =
	{
		.sem_num = 0,
		.sem_op = 1,
		.sem_flg = 0,
	};
	if (linux_semtimedop(id, &sembuf, linux_SEMOPM + 1, 0) != linux_E2BIG)
	{
		linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
		return TEST_RESULT_FAILURE;
	}

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_semid_t id;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | 0666, &id))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sembuf_t sembuf =
	{
		.sem_num = 0,
		.sem_op = 1,
		.sem_flg = 0,
	};
	if (linux_semtimedop(id, &sembuf, 1, 0))
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

	printf("Start testing semtimedop.\n");
	DO_TEST(no_access, &ret);
	DO_TEST(segfault, &ret);
	DO_TEST(too_many, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing semtimedop.\n");

	return ret;
}
