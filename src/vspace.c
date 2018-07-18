// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  vspace.c - vspace main
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2012 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <getopt.h>
#include <limits.h>
#include "common.h"
#include "parse.h"

#include <clip/clip-vserver.h>

static inline void
print_help(const char *prog)
{
	printf("%s [-hv] <xid> -- <command>\n", prog);
	puts("Run a command in some or all of the namespaces");
	puts("associated with a security context.");
	puts("Options:");
	puts("\t-h: print this help and exit");
	puts("\t-v: print the version number and exit");
	puts("\t-i: enter the ipc namespace (default all)");
	puts("\t-m: enter the vfs namespace (default all)");
	puts("\t-n: enter the net namespace (default all)");
	puts("\t-p: enter the pid namespace (default all)");
	puts("\t-u: enter the uts namespace (default all)");
	puts("\t-U: enter the usr namespace (default all)");
}

int main(int argc, char *argv[])
{
	unsigned long xid;
	char *endptr;
	char **envp;
	int c;

	/* N.B. : passing a null mask means using all
	 * the namespaces associated with the target context.
	 */
	uint64_t mask = 0;

	const char *prog = basename(argv[0]);

	while ((c = getopt(argc, argv, "hvimnpuU")) != -1) {
		switch (c) {
			case 'h':
				print_help(prog);
				return EXIT_SUCCESS;
				break;
			case 'v':
				print_version(prog);
				return EXIT_SUCCESS;
				break;
			case 'i':
				mask |= CLONE_NEWIPC;
				break;
			case 'm':
				mask |= CLONE_NEWNS|CLONE_FS;
				break;
			case 'n':
				mask |= CLONE_NEWNET;
				break;
			case 'p':
				mask |= CLONE_NEWPID;
				break;
			case 'u':
				mask |= CLONE_NEWUTS;
				break;
			case 'U':
				mask |= CLONE_NEWUSER;
				break;
			default:
				WARN("Invalid option");
				return EXIT_FAILURE;
				break;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 2) {
		WARN("Not enough arguments : %d", argc);
		print_help(prog);
		return EXIT_FAILURE;
	}

	xid = strtoul(argv[0], &endptr, 0);
	if (errno) {
		WARN("Invalid xid: %s", argv[0]);
		return EXIT_FAILURE;
	}
	if (xid > UINT_MAX) {
		WARN("xid is too big: %s", argv[0]);
		return EXIT_FAILURE;
	}
	if (!xid) {
		WARN("xid 0 cannot be entered");
		return EXIT_FAILURE;
	}
	if (*endptr != '\0')
		WARN("Trailing characters in xid %s", argv[0]);

	
	if (clip_enter_some_namespaces(xid, mask)) {
		WARN("Could not enter namespaces for context %lu", xid);
		return EXIT_FAILURE;
	}

	envp = setup_envp(0, "root", "/root");
	if (!envp) {
		WARN("Could not set up envp");
		return EXIT_FAILURE;
	}

	if (execve(argv[1], argv+1, envp))
		PERROR("execve");

	return EXIT_FAILURE;
}
