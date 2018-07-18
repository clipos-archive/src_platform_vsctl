// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  vsadm.c - vsadm main
 *  Copyright 2014 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sched.h>
#include <getopt.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>

#include "common.h"

#include <linux/capability.h>

#include <clip/clip-vserver.h>
#include <clip/clip.h>

static inline void
print_help(const char *prog)
{
	printf("%s [-hv] <command>\n", prog);
	puts("Run a command in the spectator/admin vserver context.");
	puts("Options:");
	puts("\t-h: print this help and exit");
	puts("\t-u <uid> : run <command> as uid <uid>");
	puts("\t-v: print the version number and exit");
}

static int
do_exec(uid_t uid, char **argv)
{
	char **envp;

	if (uid) {
		struct passwd *passwd = NULL;
		gid_t gid;
		int ret;

		passwd = getpwuid(uid);
		if (!passwd) {
			WARN("Failure getting account for uid %d", uid);
			return -1;
		}
		gid = passwd->pw_gid;

		ret = setgid(gid);
		if (ret) {
			WARN_ERRNO("Setgid %d failed", gid);
			return ret;
		}
		ret = initgroups(passwd->pw_name, gid);
		if (ret) {
			WARN_ERRNO("Initgroups failed for %s", 
							passwd->pw_name);
			return ret;
		}
		ret = setuid(uid);
		if (ret) {
			WARN_ERRNO("Setuid %d failed", uid);
			return ret;
		}
		envp = setup_envp(uid, passwd->pw_name, passwd->pw_dir);
	} else {
		const uint32_t caps = 
			  (1<<CAP_CHOWN) 
			| (1<<CAP_DAC_OVERRIDE)
			| (1<<CAP_DAC_READ_SEARCH)
			| (1<<CAP_FOWNER)
			| (1<<CAP_FSETID)
			| (1<<CAP_SETGID)
			| (1<<CAP_SETUID)
			| (1<<CAP_IPC_LOCK)
			| (1<<CAP_IPC_OWNER);

		/* Reduce our capabilities to something reasonable.
		 * This won't change much in terms of permitted / effective
		 * caps, which will be recalculated as soon as we execve(),
		 * but it will drop any extra inherited caps.
		 */
		if (clip_reducecaps(caps)) {
			WARN("Could not drop capabilities");
			return EXIT_FAILURE;
		}
		envp = setup_envp(uid, "root", "/root");
	}

	if (!envp) {
		WARN("Failed to set up environment");
		return -1;
	}

	execve(argv[0], argv, envp);

	/* Not reached */
	WARN_ERRNO("execve %s failed", argv[0]);
	return -1;
}

int main(int argc, char *argv[])
{
	int c;
	const char *prog = basename(argv[0]);
	char *endptr;
	uid_t uid = 0;

	while ((c = getopt(argc, argv, "hu:v")) != -1) {
		switch (c) {
			case 'h':
				print_help(prog);
				return EXIT_SUCCESS;
				break;
			case 'u':
				errno = 0;
				uid = strtoul(optarg, &endptr, 10);
				if (errno) {
					WARN("Invalid uid: %s", optarg);
					return errno;
				}
				if (uid > UINT_MAX) {
					WARN("Uid is too big: %s", optarg);
					return -ERANGE;
				}
				if (*endptr != '\0') 
					WARN("Trailing chars for uid %s", 
						optarg);
				break;
			case 'v':
				print_version(prog);
				return EXIT_SUCCESS;
				break;
			default:
				WARN("Invalid option");
				return EXIT_FAILURE;
				break;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 1) {
		WARN("Not enough arguments : %d", argc);
		print_help(prog);
		return EXIT_FAILURE;
	}

	if (clip_enter_security_context(1)) {
		WARN("Could not enter spectator context");
		return EXIT_FAILURE;
	}

	if (do_exec(uid, argv)) {
		WARN("Failed to adjust privileges");
		return EXIT_FAILURE;
	}

	return EXIT_FAILURE;
}
