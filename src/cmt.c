#define _GNU_SOURCE

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"
#include "secret.h"
#include "debug.h"
#include "ram_map.h"
#include "tests.h"
#include "debug.h"

#define TEST_NUM 6

struct char_mem_test test_set[] = {
	{"test_devmem_access", &test_devmem_access, "Test whatever /dev/mem is accessible",				F_ARCH_ALL|F_BITS_ALL|F_MISC_FATAL|F_MISC_INIT_PRV},
	{"test_strict_devmem", &test_strict_devmem, "Test Strict Devmem enabled",					F_ARCH_ALL|F_BITS_ALL|F_MISC_STRICT_DEVMEM_PRV},
	{"test_read_at_addr_32bit_ge", &test_read_at_addr_32bit_ge, "Test 64bit ppos vs 32 bit addr",			F_ARCH_ALL|F_BITS_B32|F_MISC_INIT_REQ},
	{"test_read_outside_linear_map", &test_read_outside_linear_map, "Test Read outside linear map",			F_ARCH_ALL|F_BITS_B32|F_MISC_INIT_REQ },
	{"test_read_secret_area", &test_read_secret_area, "Test that tests memfd_secret can not being accessed",	F_ARCH_ALL|F_BITS_ALL|F_MISC_INIT_REQ},
	{"test_read_allowed_area", &test_read_allowed_area, "test allowed area can be read",				F_ARCH_ALL|F_BITS_ALL|F_MISC_INIT_REQ},
//	{"", &fn, "", },
};

int main(int argc, char *argv[]) {
	int tests_skipped = 0;
	int tests_failed = 0;
	int tests_passed = 0;
	int i, tmp_res;
	struct test_context t = {0};
	char *str_res;
	struct char_mem_test *current;

	// seet verbose flag from cmdline
	t.verbose = false;
	if ((argc >= 2) && (!strcmp(argv[1], "-v"))) {
		t.verbose = true;
		pdebug=1;
	}

	t.map = parse_iomem();
	if (!t.map) goto exit;

	if (t.verbose) {
		report_physical_memory(t.map);
		dump_ram_map(t.map);
	}

	for (i=0; i < sizeof(test_set)/sizeof(test_set[0]); i++) {
		current = test_set +i;
		tmp_res = test_needed(&t, current);
		switch (tmp_res) {
		case TEST_INCOHERENT:
			deb_printf("Incoherent sequence Detected\n");
			exit(-1);
			break;
		case TEST_ALLOWED:
			deb_printf("allowed sequence Detected\n");
			str_res = "";
			printf("%s - (%s) ", current->name, current->descr);
			tmp_res = current->fn(&t);
			switch (tmp_res) {
			case FAIL:
				tests_failed++;
				str_res = KO_STR;
				break;
			case SKIPPED:
				tests_skipped++;
				str_res = SKP_STR;
				break;
			case PASS:
				tests_passed++;
				str_res = OK_STR;
				break;
			default:
				tests_failed++;
				// this should not happend:
				// TODO: exit
			}
			printf("%s\n", str_res);
			if ((tmp_res == FAIL) && (current->flags & F_MISC_FATAL)) {
				printf("fatal test failed end the chain\n");
				goto cleanup;
			}
		case TEST_DENIED:
			deb_printf("denied sequence Detected\n");
		}
	}

cleanup:
	close(t.fd);
	free_ram_map(t.map);
exit:
	printf("Run tests = %d (passed=%d, skipped=%d failed=%d)\n", tests_skipped+tests_failed+tests_passed, tests_passed, tests_skipped, tests_failed);
	return tests_skipped+tests_failed;
}
