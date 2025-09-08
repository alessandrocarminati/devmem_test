#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "tests.h"
#include "debug.h"
#include "utils.h"
#include "ram_map.h"
#include "secret.h"

int test_read_at_addr_32bit_ge(struct test_context *t) {
	if (is_64bit_arch()) {
		deb_printf("[test_read_at_addr_32bit_ge] Skipped (64-bit architecture)\n");
		return SKIPPED;
	}

	uint64_t target_addr = 0x100000000ULL;
	int ret = try_read_dev_mem(t->fd, target_addr, 0, NULL);

	if (ret == 0) {
		deb_printf("[test_read_at_addr_32bit_ge] PASS: Read beyond 4 GiB at 0x%llx returned 0 bytes\n", target_addr);
		return PASS;
	} else {
		deb_printf("[test_read_at_addr_32bit_ge] FAIL: Expected 0 bytes at 0x%llx, got %d (errno=%d)\n", target_addr,
			   ret, -ret);
		return FAIL;
	}
}

int test_read_outside_linear_map(struct test_context *t) {
	if (sizeof(void*) == 8) {
		deb_printf("[test_read_outside_linear_map] Skipped: 64-bit architecture\n");
		return SKIPPED;
	}

	if (!t->map || t->map->count == 0) {
		deb_printf("No memory map provided!\n");
		return SKIPPED;
	}

	uint64_t start_addr = t->map->regions[0].start;
	uint64_t max_addr = t->map->regions[t->map->count - 1].end;

	deb_printf("[test_read_outside_linear_map] Scanning between 0x%llx and 0x%llx\n",
		   (unsigned long long)start_addr, (unsigned long long)max_addr);

	uint64_t last_linear = find_last_linear_byte(t->fd, start_addr, max_addr);

	deb_printf("Last readable linear address: 0x%llx\n",
		   (unsigned long long)last_linear);

	uint64_t tolerance = 16 * 1024 * 1024;
	if (last_linear + 1 >= EXPECTED_LINEAR_LIMIT - tolerance &&
		last_linear + 1 <= EXPECTED_LINEAR_LIMIT + tolerance) {
		deb_printf("PASS: Linear map ends near 1 GiB boundary.\n");
		return PASS;
	} else {
		deb_printf("FAIL: Linear map ends unexpectedly (expected ~890MB).\n");
		return FAIL;
	}
}

int test_write_outside_linear_map(struct test_context *t) {
	if (sizeof(void*) == 8) {
		deb_printf("[test_write_outside_linear_map] Skipped: 64-bit architecture\n");
		return SKIPPED;
	}

	if (!t->map || t->map->count == 0) {
		deb_printf("No memory map provided!\n");
		return SKIPPED;
	}

	uint64_t start_addr = t->map->regions[0].start;
	uint64_t max_addr = t->map->regions[t->map->count - 1].end;

	deb_printf("[test_write_outside_linear_map] Scanning between 0x%llx and 0x%llx\n",
		   (unsigned long long)start_addr, (unsigned long long)max_addr);

	uint64_t last_linear = find_last_linear_byte(t->fd, start_addr, max_addr);

	deb_printf("Last readable linear address: 0x%llx\n",
		   (unsigned long long)last_linear);

	uint64_t tolerance = 16 * 1024 * 1024;
	if (last_linear + 1 >= EXPECTED_LINEAR_LIMIT - tolerance &&
		last_linear + 1 <= EXPECTED_LINEAR_LIMIT + tolerance) {
		deb_printf("PASS: Linear map ends near 1 GiB boundary.\n");
		fill_random_chars(t->srcbuf, sizeof(t->srcbuf));
		if (try_write_dev_mem(t->fd, last_linear + 0x1000, SMALL_BYTES_CNT, t->srcbuf) < 0) {
			return FAIL;
		}
		return PASS;
	} else {
		deb_printf("FAIL: Linear map ends unexpectedly (expected ~890MB).\n");
		return FAIL;
	}
}

int test_strict_devmem(struct test_context *t) {
	int res = FAIL;
	uint64_t addr;
	ssize_t ret;
	uint8_t buf;

	addr = find_high_system_ram_addr(t->map);
	if (addr == 0) {
		deb_printf("No high System RAM region found.\n");
		res = SKIPPED;
		return res;
	}

	deb_printf("Testing physical address: 0x%llx\n", addr);

	ret = pread(t->fd, &buf, 1, addr);
	if (ret < 0) {
		if (errno == EPERM) {
			deb_printf("CONFIG_STRICT_DEVMEM is ENABLED\n");
		} else if (errno == EFAULT || errno == ENXIO) {
			deb_printf("Invalid address (errno=%d). Try another region.\n", errno);
			res = SKIPPED;
		} else if (errno == EACCES) {
			deb_printf("Access blocked by LSM or lockdown (errno=EACCES).\n");
			res = SKIPPED;
		} else {
			perror("pread");
		}
	} else {
		deb_printf("CONFIG_STRICT_DEVMEM is DISABLED\n");
		res = PASS;
	}

	if (res!=PASS)
		t->strict_devmem_state = true;

	return res;
}

int test_devmem_access(struct test_context *t) {
	t->fd = open("/dev/mem", O_RDONLY);
	if (t->fd < 0) {
		return FAIL;
	}
	t->devmem_init_state = true;
	return PASS;
}

int test_read_secret_area(struct test_context *t) {
	void *tmp_ptr;
	deb_printf("\ntest_read_secret_area - start\n", tmp_ptr);
	tmp_ptr = secret_alloc(sizeof(t->dstbuf));
	
	if (tmp_ptr) {
		deb_printf("secret_alloc [ok] tmp_ptr va addr = 0x%lx\n", tmp_ptr);
		fill_random_chars(tmp_ptr, sizeof(t->dstbuf)); // lazy alloc, need to fill with something
		if (t->verbose)
			print_hex(tmp_ptr, 32);
		t->tst_addr = virt_to_phys(tmp_ptr);
		if (t->tst_addr) {
			deb_printf("filled with things -> tst_addr phy addr = 0x%lx\n", t->tst_addr);
			if (try_read_dev_mem(t->fd, t->tst_addr, sizeof(t->dstbuf), t->dstbuf) < 0)
				return PASS;
		}
	}
	return FAIL;
}

int test_read_restricted_area(struct test_context *t) {
	fill_random_chars(t->dstbuf, sizeof(t->dstbuf));
	if (t->verbose)
		print_hex(t->dstbuf, 32);
	if (t->tst_addr = pick_restricted_address(t->map)) {
		if (copy_fragmented_physical_memory(t) > 0) { // try_read_dev_mem(t->fd, t->tst_addr, sizeof(t->dstbuf), t->dstbuf) >= 0) {
			if (t->verbose)
				 print_hex(t->dstbuf, 32);

			if (is_zero(t->dstbuf, sizeof(t->dstbuf))) {
				return PASS;
			}
		}
	}
	return FAIL;
}

int test_read_allowed_area(struct test_context *t) {
	fill_random_chars(t->srcbuf, sizeof(t->srcbuf));
	if (t->tst_addr = virt_to_phys(t->srcbuf)) {
		if (copy_fragmented_physical_memory(t) > 0) { //try_read_dev_mem(t->fd, t->tst_addr, sizeof(t->dstbuf), t->dstbuf) >= 0) {
			deb_printf("Read OK  compare twos\n", t->tst_addr);
			if (t->verbose) {
				print_hex(t->srcbuf, 32);
				print_hex(t->dstbuf, 32);
				compare_and_dump_buffers(t->srcbuf, t->dstbuf, sizeof(t->dstbuf));
			}
			if (!memcmp(t->srcbuf, t->dstbuf, sizeof(t->srcbuf))) {
				return PASS;
			}
		}
	}
	return FAIL;
}

int test_read_allowed_area_ppos_advance(struct test_context *t) {
	char single_page_buf_src[SINGLE_PAGE_BUF_SIZE];
	char single_page_buf_dst[SINGLE_PAGE_BUF_SIZE];

	fill_random_chars(single_page_buf_src, SINGLE_PAGE_BUF_SIZE);
	memset(single_page_buf_dst, 0, SINGLE_PAGE_BUF_SIZE);
	if (t->verbose)
		print_hex(single_page_buf_src, 32);
	if (t->tst_addr = virt_to_phys(single_page_buf_src)) {
		deb_printf("test_read_allowed_area_ppos_advance t->tst_addr=%llx\n", t->tst_addr);
		if ((try_read_dev_mem(t->fd, t->tst_addr, SINGLE_PAGE_BUF_SIZE / 2, single_page_buf_dst) >= 0) &&
		    (try_read_inplace(t->fd, SINGLE_PAGE_BUF_SIZE / 2, single_page_buf_dst) >= 0)){
			if (t->verbose)
				print_hex(single_page_buf_dst, 32);

			if (!memcmp(single_page_buf_src + SINGLE_PAGE_BUF_SIZE / 2, single_page_buf_dst, SINGLE_PAGE_BUF_SIZE / 2)) {
				return PASS;
			}
		}
	}
	return FAIL;
}

int test_write_outside_area(struct test_context *t) {
	fill_random_chars(t->srcbuf, sizeof(t->srcbuf));
	t->tst_addr = pick_outside_address(t->map);
	if (try_write_dev_mem(t->fd, t->tst_addr, SMALL_BYTES_CNT, t->srcbuf) < 0) {
		return PASS;
	}
	return FAIL;
}

