// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  vsaddr.c - vsaddr main
 *  Copyright (C) 2012-2014 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include "common.h"
#include "parse.h"

#include <clip/clip-vserver.h>

#define ADDRS_INCREMENT	4U /* Allocation increment for ipaddrs/netmasks */
char **g_ipaddrs;
char **g_netmasks;
size_t g_num_addrs;
size_t g_next_addr;

const char *g_bcast;
const char *g_lback;

static int g_do_set = 0;
static int g_do_remove = 0;
static nid_t g_nid = 0;

static void
print_help(const char *prog)
{
	printf("%s [options] -n <nid> -s|-r [-l <addr>] [-b <addr>] "
					"[-a <addr> -a <addr> ...]\n", prog);
	puts("Actions:");
	puts("-n <nid>  : nid of the jail");
	puts("-s        : set addresses for the jail");
	puts("-r        : remove all addresses from the jail");
	puts("-a <addr> : IP address and mask to set for the jail");
	puts("-l <addr> : Loopback address to set for the jail");
	puts("-b <addr> : Broadcast address to set for the jail");
	puts("-v        : display version and exit");
	puts("-h        : display help and exit");
}

static int 
parse_addr(const char *str, size_t len)
{
	const char *ptr;
	char *tmp1, *tmp2;

	if (g_next_addr == g_num_addrs) {
		/* More space needed */
		char **tmp;

		g_num_addrs += ADDRS_INCREMENT;
		tmp = realloc(g_ipaddrs, 
					g_num_addrs * sizeof(char *));
		if (!tmp) {
			WARN("Out of memory - too many addresses");
			return -ENOMEM;
		}
		g_ipaddrs = tmp;

		tmp = realloc(g_netmasks, 
					g_num_addrs * sizeof(char *));
		if (!tmp) {
			WARN("Out of memory - too many addresses");
			return -ENOMEM;
		}
		g_netmasks = tmp;
	}

	/* Our strnchr */
	ptr = str;
	while ((size_t)(ptr - str) < len) {
		if (*ptr == '/')
			goto found;
		ptr++;
	}
	WARN("Could not find '/' in %.*s", (int) len, str);
	return -1;

found:
	tmp1 = strndup(str, (size_t)(ptr - str));
	if (!tmp1) {
		WARN("Out of memory");
		return -ENOMEM;
	}

	tmp2 = strndup(ptr + 1, len - (ptr - str + 1));
	if (!tmp2) {
		WARN("Out of memory");
		free(tmp1);
		return -ENOMEM;
	}
	(void)chomp_sep(tmp2, len - (ptr - str + 1));

	g_ipaddrs[g_next_addr] = tmp1;
	g_netmasks[g_next_addr] = tmp2;
	++g_next_addr;

	return 0;
}

static int
get_options(int argc, char *argv[])
{
	int c;
	unsigned long tmp;
	char *endptr;
	
	while ((c = getopt(argc, argv, "a:b:hl:n:rsv")) != -1) {
		switch (c) {
			case 'a':
				if (parse_addr(optarg, strlen(optarg))) {
					WARN("Failed to parse address: %s",
									optarg);
					return -EINVAL;
				}
				break;
			case 'b':
				if (g_bcast) {
					WARN("Broadcast address set "
							"multiple times");
					return -1;
				}
				g_bcast = optarg;
				break;
			case 'h':
				print_help(basename(argv[0]));
				return EXIT_SUCCESS;
				break;
			case 'l':
				if (g_lback) {
					WARN("Loopback address set "
							"multiple times");
					return -1;
				}
				g_lback = optarg;
				break;
			case 'n':
				errno = 0;
				tmp = strtoul(optarg, &endptr, 10);
				if (errno) {
					WARN("Invalid nid: %s", optarg);
					return errno;
				}
				if (tmp > UINT_MAX) {
					WARN("nid is too big: %s", optarg);
					return -ERANGE;
				}
				if (*endptr != '\0') 
					WARN("Trailing chars for nid %s", 
						optarg);
				g_nid = (nid_t)tmp;
				break;
			case 'r':
				g_do_remove = 1;
				break;
			case 's':
				g_do_set = 1;
				break;
			case 'v':
				print_version(basename(argv[0]));
				return EXIT_SUCCESS;
				break;
			default:
				return -1;
				break;
		}
	}

	if (g_do_set + g_do_remove == 0) {
		WARN("At least one of -s or -r is needed");
		return -1;
	}
	if (!g_nid) {
		WARN("No nid specified");
		return -1;
	}
	if (g_do_set && !g_num_addrs && !g_lback && !g_bcast) {
		WARN("At least one address is needed");
		return -1;
	}
	return 0;
}


static int
do_set(void)
{
	const char *bcast = NULL;
	const char *lback = NULL;

	if (g_ipaddrs) {
		bcast = (g_bcast) ? g_bcast : g_ipaddrs[0];
		lback = (g_lback) ? g_lback : g_ipaddrs[0];
	} else {
		bcast = g_bcast;
		lback = g_lback;
	}

	if (g_ipaddrs) {
		/* Grrr, stupid cast from char ** to const char ** ... */
		if (clip_net_add_addrs(g_nid, 
				(void *)g_ipaddrs, (void *)g_netmasks)) {
			WARN_ERRNO("Failed to add addresses");
			return -1;
		}
	}

	if (bcast) {
		if (clip_net_set_bcast(g_nid, bcast)) {
			WARN_ERRNO("Failed to set broadcast address");
			return -1;
		}
	}

	if (lback) {
		if (clip_net_set_lback(g_nid, lback)) {
			WARN_ERRNO("Failed to set broadcast address");
			return -1;
		}
	}

	return 0;
}

static int
do_remove(void)
{
	if (clip_net_del_addrs(g_nid)) {
		WARN_ERRNO("Failed to remove addresses");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	unsigned int i;

	if (get_options(argc, argv)) {
		WARN("Error parsing options");
		return EXIT_FAILURE;
	}
	argc -= optind;
	argv += optind;
	if (argc > 0) {
		WARN("Trailing garbage after options");
	}

	if (g_do_remove && do_remove()) {
		ret = EXIT_FAILURE;
		goto out;
	}
	if (g_do_set && do_set()) {
		ret = EXIT_FAILURE;
		goto out;
	}
	
	ret = EXIT_SUCCESS;
	/* Fall through */
out:
	if (g_ipaddrs) {
		for (i = 0; i < g_num_addrs; i++)
			free(g_ipaddrs[i]);
		free(g_ipaddrs);
	}
	if (g_netmasks) {
		for (i = 0; i < g_num_addrs; i++)
			free(g_netmasks[i]);
		free(g_netmasks);
	}

	return ret;
}
