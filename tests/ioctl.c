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

#include <unistd.h>

static enum TestResult test_invalid_fd(void)
{
	if (linux_ioctl(linux_stdout, 0, 0, 0) != linux_ENOTTY)
		return TEST_RESULT_FAILURE;

	if (linux_ioctl(linux_stderr + 1, 0, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing ioctl.\n");
	DO_TEST(invalid_fd, &ret);
	printf("Finished testing ioctl.\n");

	return ret;
}
