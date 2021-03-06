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
	if  (linux_renameat2(linux_AT_FDCWD, "some file", linux_AT_FDCWD, 0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	if  (linux_renameat2(linux_AT_FDCWD, 0, linux_AT_FDCWD, "some file", 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	if  (linux_renameat2(linux_AT_FDCWD, 0, linux_AT_FDCWD, 0, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing renameat2.\n");
	DO_TEST(segfault, &ret);
	printf("Finished testing renameat2.\n");

	return ret;
}
