#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define F_ARCH_ALL			1
#define F_ARCH_X86			(1 << 1)
#define F_ARCH_ARM			(1 << 2)
#define F_ARCH_PPC			(1 << 3)
#define F_ARCH_MIPS			(1 << 4)
#define F_ARCH_S390			(1 << 5)
#define F_ARCH_RISCV			(1 << 6)

#define F_BITS_ALL			(1 << 7)
#define F_BITS_B64			(1 << 8)
#define F_BITS_B32			(1 << 9)

#define F_MISC_FATAL			(1 << 10)
#define F_MISC_STRICT_DEVMEM_REQ	(1 << 11)
#define F_MISC_STRICT_DEVMEM_PRV	(1 << 12)
#define F_MISC_INIT_PRV			(1 << 13)
#define F_MISC_INIT_REQ			(1 << 14)
#define F_MISC_DONT_CARE		(1 << 15)
#define F_MISC_WARN_ON_SUCCESS		(1 << 16)
#define F_MISC_WARN_ON_FAILURE		(1 << 17)
/*
#define F_MISC_				(1 << 15)
#define F_MISC_				(1 << 16)
#define F_MISC_				(1 << 17)
#define F_MISC_				(1 << 18)
#define F_MISC_				(1 << 19)
#define F_MISC_				(1 << 20)
#define F_MISC_				(1 << 21)
#define F_MISC_				(1 << 22)
#define F_MISC_				(1 << 23)
#define F_MISC_				(1 << 24)
#define F_MISC_				(1 << 25)
#define F_MISC_				(1 << 26)
#define F_MISC_				(1 << 27)
#define F_MISC_				(1 << 28)
#define F_MISC_				(1 << 29)
#define F_MISC_				(1 << 30)
#define F_MISC_				(1 << 31)
*/

typedef enum {
	TEST_DENIED,
	TEST_INCOHERENT,
	TEST_ALLOWED
} test_consistency;

struct test_context {
	struct ram_map 	*map;
	char 		srcbuf[64];
	char 		dstbuf[64];
	uintptr_t	tst_addr;
	int		fd;
	bool		verbose;
	bool		strict_devmem_state;
	bool		devmem_init_state;
};

struct char_mem_test {
	char		*name;
	int		(*fn)(struct test_context *);
	char		*descr;
	uint64_t	flags;
};

int try_read_dev_mem(int, uint64_t, int, void *);
int try_write_dev_mem(int, uint64_t, int, void *);
int try_read_inplace(int, int, void *);
uint64_t virt_to_phys(void *);
int fill_random_chars(char *, int);
bool is_zero(const void *, size_t);
void print_hex(const void *, size_t);
test_consistency test_needed(struct test_context *, struct char_mem_test *);
#endif

