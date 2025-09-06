#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define EXPECTED_LINEAR_LIMIT 0x377fe000
#define LOW_MEM_LIMIT 0x100000ULL
#define SAFE_OFFSET (512ULL * 1024ULL)
#define TEST_NUM 5
#define PASS 0
#define FAIL -1
#define SKIPPED 1
#define OK_STR "\e[1;32mPASS"
#define KO_STR "\e[1;31mFAIL"
#define SKP_STR "\e[1;33mSKIP"

struct ram_region {
	uint64_t start;
	uint64_t end;
	char *name;
};

struct ram_map {
	struct ram_region *regions;
	size_t count;
};

static inline bool is_64bit_arch(void) {
	return sizeof(void*) == 8;
}

static uint64_t virt_to_phys(void *virt_addr) {
	uint64_t virt_pfn, page_size, phys_addr, pfn;
	uintptr_t virt = (uintptr_t)virt_addr;
	ssize_t bytes_read;
	uint64_t entry=0;
	off_t offset;
	int fd;

	page_size = (uint64_t)sysconf(_SC_PAGE_SIZE);
	virt_pfn = virt / page_size;

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error opening /proc/self/pagemap: %s\n", strerror(errno));
		return 0;
	}

	offset = (off_t)(virt_pfn * sizeof(uint64_t));
	if (lseek(fd, offset, SEEK_SET) == (off_t)-1) {
		fprintf(stderr, "Error seeking pagemap: %s\n", strerror(errno));
		close(fd);
		return 0;
	}

	bytes_read = read(fd, &entry, sizeof(entry));
	close(fd);
	if (bytes_read != sizeof(entry)) {
		fprintf(stderr, "Error reading pagemap: %s\n", strerror(errno));
		return 0;
	}

	if (!(entry & (1ULL << 63))) {
		fprintf(stderr, "Page not present in RAM (maybe swapped out).\n");
		return 0;
	}

	pfn = entry & ((1ULL << 55) - 1);
	if (pfn == 0) {
		fprintf(stderr, "PFN is 0 - invalid mapping.\n");
		return 0;
	}

	phys_addr = (pfn * page_size) + (virt % page_size);
	return phys_addr;
}

static int try_read_dev_mem(int fd, uint64_t addr, int scnt, void *sbuf) {
	char space;
	ssize_t r;
	void *buf;
	int cnt;

	buf = sbuf?sbuf:&space;
	cnt = sbuf?scnt:sizeof(space);
	if (lseek(fd, (off_t)addr, SEEK_SET) == (off_t)-1) {
		return -errno;
	}

	r = read(fd, buf, cnt);
	if (r < 0) {
//		printf("read(%d, 0x%lx, %d)=%d\n", fd, buf, cnt, r);
		return -errno;
	}
	return (int)r;
}

int test_read_at_addr_32bit_ge(int fd) {
	if (is_64bit_arch()) {
//		printf("[test_read_at_addr_32bit_ge] Skipped (64-bit architecture)\n");
		return SKIPPED;
	}

	uint64_t target_addr = 0x100000000ULL;
	int ret = try_read_dev_mem(fd, target_addr, 0, NULL);

	if (ret == 0) {
//		printf("[test_read_at_addr_32bit_ge] PASS: Read beyond 4 GiB at 0x%llx returned 0 bytes\n", target_addr);
		return PASS;
	} else {
//		printf("[test_read_at_addr_32bit_ge] FAIL: Expected 0 bytes at 0x%llx, got %d (errno=%d)\n", target_addr,
//			   ret, -ret);
		return FAIL;
	}
}

static uint64_t find_last_linear_byte(int fd, uint64_t low_start, uint64_t max_addr) {
	uint64_t low = low_start + SAFE_OFFSET;
	uint64_t high = max_addr;
	uint64_t last_good = 0;

	while (low <= high) {
		uint64_t mid = low + (high - low) / 2;
		int ret = try_read_dev_mem(fd, mid, 0, NULL);

		if (ret > 0) {
			last_good = mid;
			low = mid + 1;
		} else if (ret == -EFAULT) {
			if (mid == 0)
				break;
			high = mid - 1;
		} else {
			fprintf(stderr, "Unexpected error at 0x%llx: %d\n",
					(unsigned long long)mid, -ret);
			break;
		}
	}
	return last_good;
}

int test_read_outside_linear_map(int fd, const struct ram_map *map) {
	if (sizeof(void*) == 8) {
//		printf("[test_read_outside_linear_map] Skipped: 64-bit architecture\n");
		return SKIPPED;
	}

	if (!map || map->count == 0) {
//		fprintf(stderr, "No memory map provided!\n");
		return SKIPPED;
	}

	uint64_t start_addr = map->regions[0].start;
	uint64_t max_addr = map->regions[map->count - 1].end;

//	printf("[test_read_outside_linear_map] Scanning between 0x%llx and 0x%llx\n",
//		   (unsigned long long)start_addr, (unsigned long long)max_addr);

	uint64_t last_linear = find_last_linear_byte(fd, start_addr, max_addr);

//	printf("Last readable linear address: 0x%llx\n",
//		   (unsigned long long)last_linear);

	uint64_t tolerance = 16 * 1024 * 1024;
	if (last_linear + 1 >= EXPECTED_LINEAR_LIMIT - tolerance &&
		last_linear + 1 <= EXPECTED_LINEAR_LIMIT + tolerance) {
//		printf("PASS: Linear map ends near 1 GiB boundary.\n");
		return PASS;
	} else {
//		printf("FAIL: Linear map ends unexpectedly (expected ~890MB).\n");
		return FAIL;
	}
}

static int calculate_bits(uint64_t max_addr) {
	uint64_t value = max_addr + 1;
	int bits = 0;
	while (value > 0) {
		value >>= 1;
		bits++;
	}
	return bits;
}

uint64_t get_highest_ram_addr(const struct ram_map *map) {
	if (!map || map->count == 0)
		return 0;
	return map->regions[map->count - 1].end;
}

static size_t count_iomem_regions(FILE *fp) {
	char line[512];
	size_t count = 0;
	uint64_t start, end;
	char name[256];

	rewind(fp);
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%llx-%llx : %255[^\n]", &start, &end, name) == 3) {
			count++;
		}
	}
	rewind(fp);
	return count;
}

static int fill_iomem_regions(FILE *fp, struct ram_map *map) {
	char line[512];
	uint64_t start, end;
	char name[256];
	size_t idx = 0;

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%llx-%llx : %255[^\n]", &start, &end, name) == 3) {
			map->regions[idx].start = start;
			map->regions[idx].end = end;
			map->regions[idx].name = strdup(name);
			if (!map->regions[idx].name) {
				perror("strdup");
				return -1;
			}
			idx++;
		}
	}
	return 0;
}

struct ram_map *parse_iomem(void) {
	FILE *fp = fopen("/proc/iomem", "r");
	if (!fp) {
		perror("fopen /proc/iomem");
		return NULL;
	}

	size_t count = count_iomem_regions(fp);
	if (count == 0) {
		fprintf(stderr, "No parsable regions found in /proc/iomem.\n");
		fclose(fp);
		return NULL;
	}

	struct ram_map *map = calloc(1, sizeof(*map));
	if (!map) {
		perror("calloc map");
		fclose(fp);
		return NULL;
	}

	map->regions = calloc(count, sizeof(*map->regions));
	if (!map->regions) {
		perror("calloc regions");
		free(map);
		fclose(fp);
		return NULL;
	}
	map->count = count;

	if (fill_iomem_regions(fp, map) < 0) {
		fclose(fp);
		return NULL;
	}

	fclose(fp);
	return map;
}

void free_ram_map(struct ram_map *map) {
	if (!map) return;
	for (size_t i = 0; i < map->count; i++) {
		free(map->regions[i].name);
	}
	free(map->regions);
	free(map);
}

uint64_t find_high_system_ram_addr(const struct ram_map *map) {
	for (size_t i = 0; i < map->count; i++) {
		if (strstr(map->regions[i].name, "System RAM") &&
			map->regions[i].start >= LOW_MEM_LIMIT) {
			return map->regions[i].start;
		}
	}
	return 0;
}

int test_strict_devmem(const struct ram_map *map) {
	int res = FAIL;
	uint64_t addr;
	ssize_t ret;
	uint8_t buf;

	addr = find_high_system_ram_addr(map);
	if (addr == 0) {
//		fprintf(stderr, "No high System RAM region found.\n");
		res = SKIPPED;
		return res;
	}

//	printf("Testing physical address: 0x%llx\n", addr);

	int fd = open("/dev/mem", O_RDONLY);
	if (fd < 0) {
		perror("open /dev/mem");
		return res;
	}

	ret = pread(fd, &buf, 1, addr);
	if (ret < 0) {
		if (errno == EPERM) {
//			printf("CONFIG_STRICT_DEVMEM is ENABLED\n");
		} else if (errno == EFAULT || errno == ENXIO) {
//			printf("Invalid address (errno=%d). Try another region.\n", errno);
			res = SKIPPED;
		} else if (errno == EACCES) {
//			printf("Access blocked by LSM or lockdown (errno=EACCES).\n");
			res = SKIPPED;
		} else {
			perror("pread");
		}
	} else {
//		printf("CONFIG_STRICT_DEVMEM is DISABLED\n");
		res = PASS;
	}

	close(fd);
	return res;
}

void dump_ram_map(const struct ram_map *map) {
	printf("Parsed RAM map (%zu regions):\n", map->count);
	for (size_t i = 0; i < map->count; i++) {
		printf("  %016llx-%016llx : %s\n",
			   map->regions[i].start,
			   map->regions[i].end,
			   map->regions[i].name);
	}
}

void report_physical_memory(const struct ram_map *map) {
	uint64_t highest_addr = get_highest_ram_addr(map);
	if (highest_addr == 0) {
		printf("No System RAM regions detected!\n");
		return;
	}

	int bits = calculate_bits(highest_addr);
	printf("Highest physical RAM address: 0x%llx\n",
		   (unsigned long long)highest_addr);
	printf("Physical address width (installed RAM): %d bits\n", bits);
}

uint64_t pick_reserved_address(const struct ram_map *map) {
	if (!map || !map->regions || map->count == 0)
		return 0;

	for (size_t i = 0; i < map->count; i++) {
		if (!strcmp("Reserved", map->regions[i].name)) {
			uint64_t start = map->regions[i].start;
			uint64_t end   = map->regions[i].end;

			if (end > start) {
				return start + (end - start) / 2;
			}
		}
	}

	return 0;
}
static int fill_random_chars(char *buf, int cnt) {
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

void *create_protected_area(size_t size) {
	if (size == 0) {
		errno = EINVAL;
		return NULL;
	}

	int fd = syscall(SYS_memfd_secret, 0);
	if (fd == -1) {
		perror("memfd_secret failed");
		return NULL;
	}

	if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_WRITE) == -1) {
		perror("fcntl F_ADD_SEALS failed");
		close(fd);
		return NULL;
	}

	if (ftruncate(fd, size) == -1) {
		perror("ftruncate failed");
		close(fd);
		return NULL;
	}

	void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap failed");
		close(fd);
		return NULL;
	}

	close(fd);
	return addr;
}

int free_protected_area(void *addr, size_t size) {
	if (addr == NULL || size == 0) {
		errno = EINVAL;
		return -1;
	}

	if (munmap(addr, size) == -1) {
		perror("munmap failed");
		return -1;
	}

	return 0;
}
int main(int argc, char *argv[]) {
	int fd, tmp_res, res = TEST_NUM;
	char srcbuf[64], dstbuf[64];
	struct ram_map *map;
	uint64_t tst_addr;
	char *str_res;
	bool verbose;

	fill_random_chars(srcbuf, sizeof(srcbuf));
	verbose = false;
	if ((argc >= 2) && (!strcmp(argv[1], "-v")))
		verbose = true;

	map = parse_iomem();
	if (!map) goto exit;

	if (verbose) {
		report_physical_memory(map);
		dump_ram_map(map);
	}

	printf("test /dev/mem accessible and exists ");
	fd = open("/dev/mem", O_RDONLY);
	if (fd < 0) {
		printf("[%s\e[0m]\n", KO_STR);

		goto cleanup;
	}
	printf("[%s\e[0m]\n", OK_STR);
	res --;

	printf("test CONFIG_STRICT_DEVMEM is disabled ");
	tmp_res = test_strict_devmem(map);
	if (tmp_res == PASS) {
		printf("[%s\e[0m]\n", OK_STR);
		str_res = KO_STR;
		printf("test_read_at_addr_32bit_ge ");
		tmp_res = test_read_at_addr_32bit_ge(fd);
		if (tmp_res==PASS) {
			res--;
			str_res = OK_STR;
		}
		if (tmp_res == SKIPPED)
			str_res = SKP_STR;
		printf("[%s\e[0m]\n", str_res);

		str_res = KO_STR;
		printf("test read outside linear_map ");
		tmp_res = test_read_outside_linear_map(fd, map);
		if (tmp_res == PASS) {
			res--;
			str_res = OK_STR;
		}
		if (tmp_res == SKIPPED)
			str_res = SKP_STR;
		printf("[%s\e[0m]\n", str_res);

		str_res = KO_STR;
		printf("test read reserved area ");
		if (tst_addr = pick_reserved_address(map)) {
			if (try_read_dev_mem(fd, tst_addr, 0, NULL) >= 0) {
				res--;
				str_res = OK_STR;
			}
		}
		printf("[%s\e[0m]\n", str_res);

		str_res = KO_STR;
		printf("test read allowed area ");
		if (tst_addr = virt_to_phys(srcbuf)) {
			if (try_read_dev_mem(fd, tst_addr, sizeof(dstbuf), dstbuf) >= 0) {
				if (!memcmp(srcbuf, dstbuf, sizeof(srcbuf))) {
					res--;
					str_res = OK_STR;
				}
			}
		}
		printf("[%s\e[0m]\n", str_res);
	} else {
		printf("[%s\e[0m]\n", KO_STR);
	}

	close(fd);
cleanup:
	free_ram_map(map);
exit:
	printf(res==TEST_NUM?"Failure %d/%d\n":res==0?"Success %d/%d\n":"Partial %d/%d\n", TEST_NUM - res, TEST_NUM);
	return res;
}
