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

static enum TestResult test_random_read(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;
	int p[2] = {-1, -1};
	FILE* file = 0;

	if (pipe(p) == -1)
		goto cleanup;

	if (p[0] == -1 || p[1] == -1)
		goto cleanup;

	file = fopen("/dev/urandom", "r");
	if (!file)
		goto cleanup;

	char out_buf[BUFFER_SIZE] = {0};
	if (fread(out_buf, 1, sizeof out_buf, file) != sizeof out_buf)
		goto cleanup;

	size_t to_write = sizeof out_buf;
	while (to_write)
	{
		ssize_t const written = write(p[1], out_buf + (sizeof out_buf - to_write), to_write);
		if (written < 0)
			goto cleanup;
		to_write -= (size_t)written;
	}

	char in_buf[sizeof out_buf] = {0};
	if (linux_read((linux_fd_t)p[0], in_buf, sizeof in_buf, 0))
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	if (memcmp(in_buf, out_buf, sizeof in_buf))
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	ret = TEST_RESULT_SUCCESS;

cleanup:
	if (file)
		fclose(file);
	if (p[0] != -1)
		close(p[0]);
	if (p[1] != -1)
		close(p[1]);
	return ret;
}

static enum TestResult test_read_zero(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;
	int fd = -1;
	
	fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
		goto cleanup;

	char buf[BUFFER_SIZE] = {0};
	size_t result = 0;
	if (linux_read((linux_fd_t)fd, buf, 0, &result) || result)
	{
		ret = TEST_RESULT_FAILURE;
		goto cleanup;
	}

	ret = TEST_RESULT_SUCCESS;

cleanup:
	if (fd != -1)
		close(fd);
	return ret;
}

static enum TestResult test_invalid_fd(void)
{
	char buf[8] = {0};
	if (linux_read(3, buf, sizeof buf, 0) != linux_EBADF)
		return TEST_RESULT_FAILURE;

	return TEST_RESULT_SUCCESS;
}

static enum TestResult test_invalid_buf(void)
{
	enum TestResult ret = TEST_RESULT_OTHER_FAILURE;
	int fd = -1;
	
	fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
		goto cleanup;

	if (linux_read((linux_fd_t)fd, 0, BUFFER_SIZE, 0) != linux_EFAULT)
		return TEST_RESULT_FAILURE;

	ret = TEST_RESULT_SUCCESS;

cleanup:
	if (fd != -1)
		close(fd);
	return ret;
}

int main(void)
{
	int ret = EXIT_SUCCESS;

	printf("Start testing read.\n");
	DO_TEST(read_zero, &ret);
	DO_TEST(invalid_fd, &ret);
	DO_TEST(invalid_buf, &ret);
	DO_TEST(random_read, &ret);
	printf("Finished testing read.\n");

	return ret;
}
