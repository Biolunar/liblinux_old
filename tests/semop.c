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
	enum TestResult result = TEST_RESULT_SUCCESS;

	linux_semid_t id = 0;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_semop(id, 0, 1) != linux_EFAULT)
		result = TEST_RESULT_FAILURE;

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return result;
}

static enum TestResult test_invalid_sem_number(void)
{
	enum TestResult result = TEST_RESULT_SUCCESS;

	linux_semid_t id = 0;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sembuf_t const buf =
	{
		.sem_num = 1,
		.sem_op = 1,
		.sem_flg = linux_IPC_NOWAIT | linux_SEM_UNDO,
	};
	if (linux_semop(id, &buf, 1) != linux_EFBIG)
		result = TEST_RESULT_FAILURE;

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return result;
}

static enum TestResult test_invalid_id(void)
{
	struct linux_sembuf_t const buf =
	{
		.sem_num = 0,
		.sem_op = 1,
		.sem_flg = linux_IPC_NOWAIT | linux_SEM_UNDO,
	};
	if (linux_semop(-1, &buf, 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_ops_number(void)
{
	enum TestResult result = TEST_RESULT_SUCCESS;

	linux_semid_t id = 0;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sembuf_t const buf =
	{
		.sem_num = 1,
		.sem_op = 1,
		.sem_flg = linux_IPC_NOWAIT | linux_SEM_UNDO,
	};
	if (linux_semop(id, &buf, 0) != linux_EINVAL)
		result = TEST_RESULT_FAILURE;

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return result;
}

static enum TestResult test_correct_usage(void)
{
	enum TestResult result = TEST_RESULT_SUCCESS;

	linux_semid_t id = 0;
	if (linux_semget(linux_IPC_PRIVATE, 1, linux_IPC_CREAT | linux_IPC_EXCL | linux_S_IRWXU, &id))
		return TEST_RESULT_OTHER_FAILURE;

	struct linux_sembuf_t const buf =
	{
		.sem_num = 0,
		.sem_op = 1,
		.sem_flg = linux_IPC_NOWAIT | linux_SEM_UNDO,
	};
	if (linux_semop(id, &buf, 1))
		result = TEST_RESULT_FAILURE;

	linux_semctl(id, 0, linux_IPC_RMID, 0, 0);
	return result;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing semop.\n");
	DO_TEST(segfault, &ret);
	DO_TEST(invalid_sem_number, &ret);
	DO_TEST(invalid_id, &ret);
	DO_TEST(invalid_ops_number, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing semop.\n");

	return ret;
}
