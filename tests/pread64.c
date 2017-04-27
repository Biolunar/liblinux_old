#include "test.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <liblinux/linux.h>

#define BUFFER_SIZE 512

static enum TestResult test_invalid_fd(void)
{
	char buf[BUFFER_SIZE] = {0};
	if (linux_pread64(linux_stderr + 1, buf, sizeof buf, 0, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_buf(void)
{
	int const fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	if (linux_pread64((linux_fd_t)fd, 0, BUFFER_SIZE, 0, 0) != linux_EFAULT)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_read_zero(void)
{
	int const fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	char buf[BUFFER_SIZE] = {0};
	size_t result = 0;
	if (linux_pread64((linux_fd_t)fd, buf, 0, 0, &result) || result)
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_read(void)
{
	linux_loff_t const offset = 123;

	int const fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
		return TEST_RESULT_OTHER_FAILURE;

	char buf[BUFFER_SIZE] = {0};
	if (linux_pread64((linux_fd_t)fd, buf, sizeof buf, offset, 0))
	{
		close(fd);
		return TEST_RESULT_FAILURE;
	}

	close(fd);
	return TEST_RESULT_SUCCESS;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing pread64.\n");
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_buf, &ret);
	DO_TEST(read_zero, &ret);
	DO_TEST(read, &ret);
	printf("Finished testing pread64.\n");

	return ret;
}
