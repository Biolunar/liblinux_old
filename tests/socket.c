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

static enum TestResult test_invalid_address_family(void)
{
	if (linux_socket(-1, linux_SOCK_STREAM, 0, 0) != linux_EAFNOSUPPORT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_type(void)
{
	if (linux_socket(linux_AF_INET, -1, 0, 0) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_correct_usage(void)
{
	linux_fd_t fd = (linux_fd_t)-1;
	if (linux_socket(linux_AF_INET, linux_SOCK_STREAM, 0, &fd) || fd == (linux_fd_t)-1)
		return TEST_RESULT_FAILURE;

	linux_close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing socket.\n");
	DO_TEST(invalid_address_family, &ret);
	DO_TEST(invalid_type, &ret);
	DO_TEST(correct_usage, &ret);
	printf("Finished testing socket.\n");

	return ret;
}
