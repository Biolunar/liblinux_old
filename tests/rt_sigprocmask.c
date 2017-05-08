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

static size_t const size = sizeof(linux_sigset_t);

static enum TestResult test_invalid_size(void)
{
	if (linux_rt_sigprocmask(linux_SIG_BLOCK, 0, 0, size - 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	if (linux_rt_sigprocmask(linux_SIG_BLOCK, 0, 0, size + 1) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_how(void)
{
	linux_sigset_t empty;
	linux_sigemptyset(&empty);

	if (linux_rt_sigprocmask(linux_SIG_BLOCK - 1, &empty, 0, size) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	if (linux_rt_sigprocmask(linux_SIG_SETMASK + 1, &empty, 0, size) != linux_EINVAL)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_get_old(void)
{
	linux_sigset_t old;
	if (linux_rt_sigprocmask(0, 0, &old, size))
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing rt_sigprocmask.\n");
	DO_TEST(invalid_size, &ret);
	DO_TEST(invalid_how, &ret);
	DO_TEST(get_old, &ret);
	printf("Finished testing rt_sigprocmask.\n");

	return ret;
}
