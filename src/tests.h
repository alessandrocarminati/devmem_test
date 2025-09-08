#ifndef TESTS_H
#define TESTS_H

#include "utils.h"

#define EXPECTED_LINEAR_LIMIT 0x377fe000
#define PASS 0
#define FAIL -1
#define SKIPPED 1
#define OK_STR "[\e[1;32mPASS\e[0m]"
#define KO_STR "[\e[1;31mFAIL\e[0m]"
#define SKP_STR "[\e[1;33mSKIP\e[0m]"


int test_read_at_addr_32bit_ge(struct test_context *);
int test_read_outside_linear_map(struct test_context *);
int test_strict_devmem(struct test_context *);
int test_devmem_access(struct test_context *);
int test_read_secret_area(struct test_context *);
int test_read_allowed_area(struct test_context *);
int test_read_reserved_area(struct test_context *);
int test_read_allowed_area(struct test_context *);

static inline bool is_64bit_arch(void) {
	return sizeof(void*) == 8;
}

#endif
