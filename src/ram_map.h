#ifndef RAM_MAP_H
#define RAM_MAP_H

#define _GNU_SOURCE
#define SAFE_OFFSET (512ULL * 1024ULL)
#define LOW_MEM_LIMIT 0x100000ULL

struct ram_region {
	uint64_t start;
	uint64_t end;
	char *name;
};

struct ram_map {
	struct ram_region *regions;
	size_t count;
};

struct ram_map *parse_iomem(void);
void free_ram_map(struct ram_map *);
uint64_t find_last_linear_byte(int, uint64_t, uint64_t);
void dump_ram_map(const struct ram_map *);
void report_physical_memory(const struct ram_map *);
uint64_t find_high_system_ram_addr(const struct ram_map *);
uint64_t pick_reserved_address(const struct ram_map *);

#endif
