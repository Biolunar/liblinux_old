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

#ifndef HEADER_LIBLINUX_TESTS_TEST_H_INCLUDED
#define HEADER_LIBLINUX_TESTS_TEST_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>

enum TestResult
{
	TEST_RESULT_SUCCESS,
	TEST_RESULT_FAILURE,
	TEST_RESULT_OTHER_FAILURE,

	TEST_RESULT_MAX,
};

static inline void do_test(enum TestResult test(void), char const* name, int result[static 1])
{
	printf(u8"\tTesting %s… ", name);
	enum TestResult const ret = test();
	switch (ret)
	{
		case TEST_RESULT_SUCCESS: printf(u8"\x1B[32mSUCCESS\x1B[0m\n"); break;
		case TEST_RESULT_FAILURE: printf(u8"\x1B[31mFAILURE\x1B[0m\n"); break;
		default: printf(u8"OTHER FAILURE\n"); break;
	}

	if (ret)
		*result = EXIT_FAILURE;
}

#define DO_TEST(name, ret)                           \
	do {                                         \
		do_test(test_ ## name, # name, ret); \
	} while (0)

#endif // !HEADER_LIBLINUX_TESTS_TEST_H_INCLUDED
