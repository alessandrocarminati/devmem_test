#define _FILE_OFFSET_BITS 64
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"
#include "debug.h"


static inline uint64_t get_page_size(void) {
	return (uint64_t)sysconf(_SC_PAGE_SIZE);
}
/*
	copies test context srcbuf to dstbuf by following srcbuf in physical memory
	and read its contents in dstbuf
	returns -1 on error
		 0 on successfully transfer with no contiguos page detected in physical memory
		 size of srcbuf on success with contiguous pages.
 */
int copy_fragmented_physical_memory(struct test_context *t) {
	uintptr_t current_virt_addr, current_dest_addr, page_offset;
	size_t bytes_to_copy, page_size, chunk_size;
	uint64_t phys_addr, prev_phys_addr;
	bool contiguos_detect;

	current_virt_addr = (uintptr_t)t->srcbuf;
	current_dest_addr = (uintptr_t)t->dstbuf;
	bytes_to_copy = t->buffsize;

	page_size = get_page_size();
	phys_addr = 0;
	contiguos_detect = false;

	while (bytes_to_copy > 0) {
		prev_phys_addr = phys_addr;
		phys_addr = virt_to_phys((void *)current_virt_addr);
		if (phys_addr == 0) {
			deb_printf("Error: Failed to get physical address for virtual address %p\n", (void *)current_virt_addr);
			return -1;
		}
		if (prev_phys_addr + page_size == phys_addr)
			contiguos_detect = true;

		page_offset = current_virt_addr % page_size;

		chunk_size = page_size - page_offset;
		if (chunk_size > bytes_to_copy) {
			chunk_size = bytes_to_copy;
		}

		if (lseek(t->fd, phys_addr, SEEK_SET) == (off_t)-1) {
			deb_printf("Failed to lseek in /dev/mem");
			return -1;
		}

		if (read(t->fd, (void *)current_dest_addr, chunk_size) != chunk_size) {
			deb_printf("Failed to read from /dev/mem");
			return -1;
		}

		current_virt_addr += chunk_size;
		current_dest_addr += chunk_size;
		bytes_to_copy -= chunk_size;
	}
	deb_printf("copy_fragmented_physical_memory ended -> contiguos_detect = %d\n", contiguos_detect);
	return contiguos_detect?t->buffsize:0;
}

static void hexdump(const void *data, size_t size, size_t offset) {
	const unsigned char *p = (const unsigned char *)data;
	size_t i, j;

	for (i = 0; i < size; i += 16) {
		printf("%08zx  ", offset + i);

		for (j = 0; j < 16; j++) {
			if (i + j < size) {
				printf("%02x ", p[i + j]);
			} else {
				printf("   ");
			}
		}
		printf(" ");

		for (j = 0; j < 16; j++) {
			if (i + j < size) {
				printf("%c", isprint(p[i + j]) ? p[i + j] : '.');
			}
		}
		printf("\n");
	}
}

void compare_and_dump_buffers(const char *buf1, const char *buf2, size_t size) {
	if (buf1 == NULL || buf2 == NULL) {
		fprintf(stderr, "Error: One or both buffers are NULL.\n");
		return;
	}

	size_t i;
	int found_difference = 0;

	for (i = 0; i < size; i += 16) {
		if (memcmp(buf1 + i, buf2 + i, 16) != 0) {
			found_difference = 1;
			printf("Difference found at offset 0x%zx (decimal %zu).\n", i, i);
			printf("--- Buffer 1 ---\n");
			hexdump(buf1 + i, 16, i);
			printf("--- Buffer 2 ---\n");
			hexdump(buf2 + i, 16, i);
			printf("\n");
		}
	}

	if (!found_difference) {
		printf("Buffers are identical.\n");
	}
}

uint64_t virt_to_phys(void *virt_addr) {
	uint64_t virt_pfn, page_size, phys_addr, pfn;
	uintptr_t virt = (uintptr_t)virt_addr;
	ssize_t bytes_read;
	uint64_t entry=0;
	off_t offset;
	int fd;

	deb_printf("virt_to_phys(%p)\n", virt_addr);

	page_size = get_page_size();
	virt_pfn = virt / page_size;
	deb_printf("page_size=%d, virt_pfn=%lu\n", page_size, virt_pfn);

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		deb_printf("Error opening /proc/self/pagemap: %s\n", strerror(errno));
		return 0;
	}

	offset = (off_t)(virt_pfn * sizeof(uint64_t));
	deb_printf("lseek(%d, 0x%llx, SEEK_SET)\n", fd, offset);
	if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
		deb_printf("Error seeking pagemap: %s\n", strerror(errno));
		close(fd);
		return 0;
	}

	bytes_read = read(fd, &entry, sizeof(entry));
	close(fd);
	if (bytes_read != sizeof(entry)) {
		deb_printf("Error reading pagemap: %s\n", strerror(errno));
		return 0;
	}

	if (!(entry & (1ULL << 63))) {
		deb_printf("Page not present in RAM (maybe swapped out).\n");
		return 0;
	}

	pfn = entry & ((1ULL << 55) - 1);
	deb_printf("entry=%llx, pfn=%llx\n", entry, pfn);
	if (pfn == 0) {
		deb_printf("PFN is 0 - invalid mapping.\n");
		return 0;
	}

	phys_addr = (pfn * page_size) + (virt % page_size);
	deb_printf("phys_addr=%llx\n", phys_addr);
	return phys_addr;
}


int try_read_inplace(int fd, int scnt, void *sbuf) {
	ssize_t r;

	deb_printf("try_read_inplace(%d, %u, %p)\n", fd, scnt, sbuf);

	r = read(fd, sbuf, scnt);
	deb_printf("read(%d, %p, %d)=%d(%d)\n", fd, sbuf, scnt, r, -errno);
	if (r < 0) {
		return -errno;
	}
	return (int)r;
}

int try_read_dev_mem(int fd, uint64_t addr, int scnt, void *sbuf) {
	int space;
	ssize_t r;
	void *buf;
	int cnt;

	deb_printf("try_read_dev_mem(%d, 0x%llx, %u, %p)\n", fd, addr, scnt, sbuf);
	buf = sbuf?sbuf:&space;
	cnt = sbuf?scnt:sizeof(space);
	deb_printf("buf = %p, cnt = %d\n", buf, cnt);
	if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1) {
		return -errno;
	}
	deb_printf("lseek(%d, %llx, SEEK_SET)=%d\n", fd, addr, -errno);

	r = read(fd, buf, cnt);
	deb_printf("read(%d, %p, %d)=%d(%d)\n", fd, buf, cnt, r, -errno);
	if (r < 0) {
		return -errno;
	}
	return (int)r;
}

int try_write_dev_mem(int fd, uint64_t addr, int scnt, void *sbuf) {
	int space;
	ssize_t r;
	void *buf;
	int cnt;

	deb_printf("try_write_dev_mem(%d, 0x%llx, %u, %p)\n", fd, addr, scnt, sbuf);
	buf = sbuf?sbuf:&space;
	cnt = sbuf?scnt:sizeof(space);
	deb_printf("buf = %p, cnt = %d\n", buf, cnt);
	if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1) {
		return -errno;
	}
	deb_printf("lseek(%d, %llx, SEEK_SET)=%d\n", fd, addr, -errno);

	r = write(fd, buf, cnt);
	deb_printf("write(%d, %p, %d)=%d(%d)\n", fd, buf, cnt, r, -errno);
	if (r < 0) {
		return -errno;
	}
	return (int)r;
}

int fill_random_chars(char *buf, int cnt) {
	if (!buf || cnt <= 0) {
		errno = EINVAL;
		return -1;
	}

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror("open /dev/urandom");
		return -1;
	}

	int bytes_read = 0;
	while (bytes_read < cnt) {
		ssize_t res = read(fd, buf + bytes_read, cnt - bytes_read);
		if (res < 0) {
			if (errno == EINTR)
				continue;
			perror("read /dev/urandom");
			close(fd);
			return -1;
		}
		bytes_read += res;
	}
	close(fd);

	return 0;
}

bool is_zero(const void *p, size_t cnt) {
	const char *byte_ptr = (const char *)p;
	for (size_t i = 0; i < cnt; ++i) {
		if (byte_ptr[i] != 0) {
			return false;
		}
	}
	return true;
}

void print_hex(const void *p, size_t cnt) {
	const unsigned char *bytes = (const unsigned char *)p;
	size_t i;

	for (i = 0; i < cnt; i++) {
		if (i % 16 == 0) {
			if (i > 0) {
				printf("\n");
			}
			printf("%08lX: ", (unsigned long)(bytes + i));
		}
		printf("%02X ", bytes[i]);
	}

	int remainder = cnt % 16;
	if (remainder != 0) {
		for (int j = 0; j < 16 - remainder; j++) {
			printf("   ");
		}
	}

	printf("\n");
}

static bool machine_is_compatible(unsigned int flags) {
	unsigned int current_arch_flag = 0;
	unsigned int current_bits_flag = 0;

#if defined(__x86_64__) || defined(__i386__)
	current_arch_flag = F_ARCH_X86;
#elif defined(__arm__) || defined(__aarch64__)
	current_arch_flag = F_ARCH_ARM;
#elif defined(__PPC__) || defined(__powerpc__)
	current_arch_flag = F_ARCH_PPC;
#elif defined(__mips__)
	current_arch_flag = F_ARCH_MIPS;
#elif defined(__s390__)
	current_arch_flag = F_ARCH_S390;
#elif defined(__riscv)
	current_arch_flag = F_ARCH_RISCV;
#else
	current_arch_flag = 0;
#endif

	if (sizeof(void*) == 8) {
		current_bits_flag = F_BITS_B64;
	} else {
		current_bits_flag = F_BITS_B32;
	}

	bool arch_matches = (flags & F_ARCH_ALL) || (flags & current_arch_flag);

	bool bits_matches = (flags & F_BITS_ALL) || (flags & current_bits_flag);

	return arch_matches && bits_matches;
}

void print_flags(uint32_t flags) {
	printf("Flags: 0x%08X ->", flags);

	// Architecture flags
	printf(" Architecture: ");
	if (flags & F_ARCH_ALL) {
		printf("ALL ");
	}
	if (flags & F_ARCH_X86) {
		printf("X86 ");
	}
	if (flags & F_ARCH_ARM) {
		printf("ARM ");
	}
	if (flags & F_ARCH_PPC) {
		printf("PPC ");
	}
	if (flags & F_ARCH_MIPS) {
		printf("MIPS ");
	}
	if (flags & F_ARCH_S390) {
		printf("S390 ");
	}
	if (flags & F_ARCH_RISCV) {
		printf("RISC-V ");
	}

	// Bitness flags
	printf(" Bitness: ");
	if (flags & F_BITS_ALL) {
		printf("ALL ");
	}
	if (flags & F_BITS_B64) {
		printf("64-bit ");
	}
	if (flags & F_BITS_B32) {
		printf("32-bit ");
	}

	// Miscellaneous flags
	printf(" Miscellaneous:");
	if (flags & F_MISC_FATAL) {
		printf("	- F_MISC_FATAL: true");
	}
	if (flags & F_MISC_STRICT_DEVMEM_REQ) {
		printf("	- F_MISC_STRICT_DEVMEM_REQ: true");
	}
	if (flags & F_MISC_STRICT_DEVMEM_PRV) {
		printf("	- F_MISC_STRICT_DEVMEM_PRV: true");
	}
	if (flags & F_MISC_INIT_PRV) {
		printf("	- F_MISC_INIT_PRV: true");
	}
	if (flags & F_MISC_INIT_REQ) {
		printf("	- F_MISC_INIT_REQ: true");
	}
	printf("\n");
}

void print_context(struct test_context *t){
	char *c;
	c="NO";
	if (t->devmem_init_state) c="yes";
	printf("system state: init=%s, ", c);
	c="NO";
	if (t->strict_devmem_state) c="yes";
	printf("strict_devmem=%s\n", c);
}

test_consistency test_needed(struct test_context *t, struct char_mem_test *current){
	if (t->verbose) {
		print_context(t);
		print_flags(current->flags);
	}

	if (!(t->devmem_init_state) && !(current->flags & F_MISC_INIT_PRV)) {
		deb_printf("Not initialized and test does not provide initialization\n");
		return TEST_DENIED;	// Not initialized and test does not provide initialization
	}
	if ((t->devmem_init_state) && (current->flags & F_MISC_INIT_PRV)){
		deb_printf("can not initialize again\n");
		return TEST_INCOHERENT;	// can not initialize again
	}
	if (!(t->devmem_init_state) && (current->flags & F_MISC_INIT_PRV)) {
		deb_printf("initializing: test allowed!\n");
		return TEST_ALLOWED; 	// initializing: test allowed!
	}
	if (!(t->devmem_init_state)) {
		deb_printf("not initialized, can not proceed\n");
		return TEST_DENIED;	// not initialized, can not proceed
	}
	if (!(machine_is_compatible(current->flags))) {
		deb_printf("not for this architecture\n");
		return TEST_DENIED;	// not for this architecture
	}
	if (((t->strict_devmem_state) || (current->flags & F_MISC_STRICT_DEVMEM_REQ)) &&
	    !((t->strict_devmem_state) && (current->flags & F_MISC_STRICT_DEVMEM_REQ))) {
		deb_printf("strict_devmem requirement and offering do not meet\n");
		return TEST_DENIED;	// strict_devmem requirement and offering do not meet
	}
	deb_printf("test allowed!\n");
	return TEST_ALLOWED;
}

void *find_contiguous_pair(void *virt_addr, size_t size) {
	size_t pgsize = get_page_size();
	size_t npages = size / pgsize;
	unsigned char *base = (unsigned char *)virt_addr;

	if (npages < 2) return NULL;

	uint64_t prev_phys = virt_to_phys(base);
	if (!prev_phys) return NULL;
//	printf(">>>> %llx\n", virt_addr);
	for (size_t i = 1; i < npages; ++i) {
		uint64_t phys = virt_to_phys(base + i * pgsize);
		if (!phys) return NULL;
//		printf("==>>>> %llx\n", phys);
		if (phys == prev_phys + pgsize) {
			// Found physically contiguous pair
			return base + (i - 1) * pgsize;
		}
		prev_phys = phys;
	}
	return NULL;
}

static void *allocator(size_t size) {
	size_t pgsize = get_page_size();
	void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}

	// Touch each page to force physical allocation
	volatile unsigned char *c = (volatile unsigned char *)p;
	for (size_t off = 0; off < size; off += pgsize) {
		c[off] = 1;
	}

	if (madvise(p, size, MADV_WILLNEED) != 0) {
		perror("madvise");
	}
	if (msync(p, size, MS_SYNC) != 0) {
		perror("msync");
	}
	sched_yield(); 
	return p;
}

static void fragment_allocator(size_t total_pages, size_t block_pages) {
	size_t pgsize = get_page_size();
	size_t blocks = (total_pages + block_pages - 1) / block_pages;
	void **list = calloc(blocks, sizeof(void *));
	if (!list) return;

	for (size_t i = 0; i < blocks; ++i) {
		list[i] = mmap(NULL, block_pages * pgsize, PROT_READ | PROT_WRITE,
					   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (list[i] == MAP_FAILED) {
			list[i] = NULL;
			continue;
		}
		unsigned char *c = (unsigned char *)list[i];
		for (size_t off = 0; off < block_pages * pgsize; off += pgsize)
			c[off] = (unsigned char)(c[off] + 1);
	}

	// Free in pseudo-random order
	for (size_t i = 0; i < blocks; ++i) {
		size_t idx = (i * 997) % blocks;
		if (list[idx]) munmap(list[idx], block_pages * pgsize);
	}

	free(list);
}

void dealloc(void *p, size_t size) {
	// Perturb allocator before freeing
	fragment_allocator(FRAG_TOTAL_PAGES, FRAG_BLOCK_PAGES);

	if (munmap(p, size) != 0) {
		perror("munmap");
	}
	fragment_allocator(FRAG_TOTAL_PAGES/2, FRAG_BLOCK_PAGES);
}

void *find_contiguous_zone(size_t size, int max_iterations) {
	for (int attempt = 0; attempt < max_iterations; ++attempt) {
		void *zone = allocator(size);
		if (!zone) {
			fprintf(stderr, "Allocator failed on iteration %d\n", attempt + 1);
			return NULL;
		}

		void *found = find_contiguous_pair(zone, size);
		if (found) {
			printf("Found contiguous pair on iteration %d at virtual address %p\n",
				   attempt + 1, found);
			return zone;  // Keep zone mapped and return base pointer
		}

		// No contiguous pair found, perturb and free
		dealloc(zone, size);
	}

	fprintf(stderr, "Failed to find contiguous pair after %d iterations.\n",
			max_iterations);
	return NULL;
}

/*====================================================================================================================*/

/* Read the PFN array for a buffer in one go */
static int walk_pagemap(void *base, size_t size, uint64_t *pfns) {
	size_t pg = get_page_size();
	size_t npages = size / pg;

	int fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		perror("open pagemap");
		return -1;
	}

	for (size_t i = 0; i < npages; i++) {
		uintptr_t vaddr = (uintptr_t)base + i * pg;
		off_t offset = (vaddr / pg) * sizeof(uint64_t);

		if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
			perror("lseek pagemap");
			close(fd);
			return -1;
		}

		uint64_t entry;
		if (read(fd, &entry, sizeof(entry)) != sizeof(entry)) {
			perror("read pagemap");
			close(fd);
			return -1;
		}

		if (!(entry & (1ULL << 63))) {
			pfns[i] = 0;  // Page not present
		} else {
			pfns[i] = entry & ((1ULL << 55) - 1);  // extract PFN
		}
	}

	close(fd);
	return 0;
}

/* Find a contiguous pair of physical pages anywhere in the buffer */
static struct contiguous_page *find_contiguous_pair_cpage(void *buf, size_t size) {
	size_t pg = get_page_size();
	size_t npages = size / pg;
	uint64_t pfns[npages];

	if (walk_pagemap(buf, size, pfns) != 0)
		return NULL;

	for (size_t i = 0; i < npages; i++) {
		if (pfns[i] == 0) continue;
		for (size_t j = 0; j < npages; j++) {
			if (i == j) continue;
			if (pfns[j] == pfns[i] + 1) {
				// Found physically contiguous pages
				struct contiguous_page *c = malloc(sizeof(*c));
				c->buffer = buf;
				c->size = size;
				c->cpagesize = pg * 2;
				c->contig_vaddr[0] = (void *)((uintptr_t)buf + i * pg);
				c->contig_vaddr[1] = (void *)((uintptr_t)buf + j * pg);
				c->contig_phys[0] = pfns[i] * pg;
				c->contig_phys[1] = pfns[j] * pg;
				return c;
			}
		}
	}
	return NULL;
}

/* Main search loop */
struct contiguous_page *find_zone_with_contiguous_pair(int max_iter) {
	for (int i = 0; i < max_iter; i++) {
		void *buf = allocator(FIXED_BUFFER_SIZE);
		if (!buf)
			return NULL;

		struct contiguous_page *c = find_contiguous_pair_cpage(buf, FIXED_BUFFER_SIZE);
		if (c) {
			return c;  // Success!
		}

	dealloc(buf, FIXED_BUFFER_SIZE);
	}
	return NULL;
}


/**
 * Write a single byte at the specified logical index
 * into the physically contiguous two-page area.
 */
void write_cpage_buf(struct contiguous_page *buf, size_t index, char data) {
	size_t pg = get_page_size();
	if (!buf) return;

	if (index < pg) {
		// First page
		((char *)buf->contig_vaddr[0])[index] = data;
	} else if (index < 2 * pg) {
		// Second page
		((char *)buf->contig_vaddr[1])[index - pg] = data;
	} else {
		// Out of bounds
		// Optionally handle error
	}
}

/**
 * Read a single byte from the specified logical index
 * in the physically contiguous two-page area.
 */
char read_cpage_buf(struct contiguous_page *buf, size_t index) {
	size_t pg = get_page_size();
	if (!buf) return 0;

	if (index < pg) {
		// First page
		return ((char *)buf->contig_vaddr[0])[index];
	} else if (index < 2 * pg) {
		// Second page
		return ((char *)buf->contig_vaddr[1])[index - pg];
	} else {
		// Out of bounds
		return 0;
	}
}

void free_cpage(struct contiguous_page *c) {
	if (!c) return;
	dealloc(buf, FIXED_BUFFER_SIZE);
	free(c);
}

int fill_random_chars_cpage(struct contiguous_page *c, int cnt) {
	char * buf;

	buf = malloc(c->cpagesize);
	if (!buf) return -1;

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror("open /dev/urandom");
		return -1;
	}

	int bytes_read = 0;
	while (bytes_read < cnt) {
		ssize_t res = read(fd, buf + bytes_read, cnt - bytes_read);
		if (res < 0) {
			if (errno == EINTR)
				continue;
			perror("read /dev/urandom");
			close(fd);
			return -1;
		}
		bytes_read += res;
	}
	close(fd);
	for (int i=0; i<cnt; i++)
		write_cpage_buf(c, i, *(buf+i));

	return 0;
}

bool is_zero_cpage(struct contiguous_page *c, size_t cnt) {
	const char *byte_ptr = (const char *)p;
	for (size_t i = 0; i < cnt; ++i) {
		if (read_cpage_buf(c, i) != 0) {
			return false;
		}
	}
	return true;
}

static int memcmp_cpage(struct contiguous_page *c1, struct contiguous_page *c2, size_t size) {
	size_t i;
	unsigned char val1, val2;

	for (i = 0; i < size; ++i) {
		val1 = (unsigned char)read_cpage_buf(c1, i);
		val2 = (unsigned char)read_cpage_buf(c2, i);

		if (val1 != val2) {
			return val1 - val2;
		}
	}

	return 0;
}

static void hexdump_cpage(struct contiguous_page *data, size_t size, size_t offset) {
	size_t i, j;

	for (i = 0; i < size; i += 16) {
		printf("%08zx  ", offset + i);

		for (j = 0; j < 16; j++) {
			if (i + j < size) {
				printf("%02x ", (unsigned char)read_cpage_buf(data,i + j));
			} else {
				printf("   ");
			}
		}
		printf(" ");

		for (j = 0; j < 16; j++) {
			if (i + j < size) {
				printf("%c", isprint((unsigned char)read_cpage_buf(data,i + j) ? (unsigned char)read_cpage_buf(data,i + j) : '.');
			}
		}
		printf("\n");
	}
}

void compare_and_dump_buffers_cpage(struct contiguous_page *c1, struct contiguous_page *c2, size_t size) {
	if (c1 == NULL || c2 == NULL) {
		fprintf(stderr, "Error: One or both buffers are NULL.\n");
		return;
	}

	size_t i;
	int found_difference = 0;

	for (i = 0; i < size; i += 16) {
		if (memcmp_cpage(c1 + i, c2 + i, 16) != 0) {
			found_difference = 1;
			printf("Difference found at offset 0x%zx (decimal %zu).\n", i, i);
			printf("--- Buffer 1 ---\n");
			hexdump_cpage(buf1 + i, 16, i);
			printf("--- Buffer 2 ---\n");
			hexdump_cpage(buf2 + i, 16, i);
			printf("\n");
		}
	}

	if (!found_difference) {
		printf("Buffers are identical.\n");
	}
}
