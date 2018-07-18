// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  vsctl.c - vsctl main
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
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "vsctl.h"
#include "conf.h"

#include <clip/clip.h>
#include <clip/clip-vserver.h>

#define TO_STR(var) _TO_STR(var)
#define _TO_STR(var) #var

#define _CONF_BASE TO_STR(CONFIG_BASE)

uid_t g_uid;
gid_t g_gid;
const char *g_chrootpath;
int g_daemonize;
const char *g_cookie;
char *g_envline;
int g_vlogin;
int g_vlogin_post;
static const char *g_stdin_path = NULL;
static const char *g_stdout_path = NULL;

char **g_cmdline;

typedef enum {
	ActionStart,
	ActionStop,
	ActionSetup,
	ActionEndSetup,
	ActionCookie,
	ActionEnter,
#ifdef TESTING
	ActionMount,
	ActionUmount,
#endif
	InvalidAction
} action_t;

typedef struct {
	const char *name;
	action_t action;
} action_map_t;

static const action_map_t g_action_map[] = {
	{ "start",	ActionStart },
	{ "stop", 	ActionStop },
	{ "setup",	ActionSetup },
	{ "endsetup", 	ActionEndSetup },
	{ "cookie",	ActionCookie },
	{ "enter", 	ActionEnter },
#ifdef TESTING
	{ "mount", 	ActionMount },
	{ "umount", 	ActionUmount },
#endif
	{ NULL, InvalidAction }
};

static inline action_t 
get_action(const char *arg)
{
	const action_map_t *iter = g_action_map;

	while (iter->name) {
		if (!strcmp(arg, iter->name))
			return iter->action;
		iter++;
	}
	return InvalidAction;
}

#define PRIVS_OFF 0
#define PRIVS_ON  1
#define UNPRIVILEGED_GID 250U
#define UNPRIVILEGED_UID 250U

static inline int 
set_privs(int privs)
{
	int ret;
	uid_t uid = (privs == PRIVS_OFF) ? UNPRIVILEGED_UID : 0;
	gid_t gid = (privs == PRIVS_OFF) ? UNPRIVILEGED_GID : 0;

	/* Make it possible to run with -p as non-root user */
	if (privs == PRIVS_OFF && geteuid())
		return 0;

	ret = setegid(gid);
	if (ret) {
		PERROR("setegid");
		return ret;
	}
	ret = seteuid(uid);
	if (ret) {
		PERROR("seteuid");
		return ret;
	}
	return 0;
}

static void
print_help(const char *prog)
{
	const action_map_t *iter = g_action_map;
	printf("%s [options] <jailname> <action>\n", prog);
	puts("Actions:");
	while (iter->name) {
		fputs(iter->name, stdout);
		iter++;
		if (iter->name)
			putchar(',');
		else 
			putchar('\n');
	}
	puts("Options:");
	puts("-a <addr> : IP address and mask for the jail (start/setup)");
	puts("-b <addr> : IP address to use as broadcast address");
	puts("-c <path> : chroot path inside the jail (enter)");
	puts("-d        : daemonize");
	puts("-e <env>  : initial environment inside jail (start/enter), where");
	puts("            <env> is defined as \"VAR1=val1[%VAR2=val2]\"");
	puts("-g <gid>  : gid to change to inside the jail (start/enter/stop)");
	puts("-h        : display this help and exit");
	puts("-i <path> : use <path> as stdin for the vsctl process");
	puts("-l <addr> : IP address to use as loopback address");
	puts("-o <path> : use <path> as stdout and stderr for the vsctl process");
	puts("-t        : set up terminal proxy outside the new context");
	puts("-T        : set up terminal proxy inside the new context (enter)");
	puts("-u <uid>  : uid to change to inside the jail (start/enter/stop)");
	puts("-v        : display version and exit");
}




static int
get_options(struct vserver_conf *conf, int argc, char *argv[])
{
	int c;
	char *endptr;
	int ret;

	#define str2id(id, name, str) do { \
		errno = 0; \
		id = strtoul(str, &endptr, 10); \
		if (errno) { \
			WARN("Invalid %s: %s", name, str); \
			return errno; \
		} \
		if (id > UINT_MAX) { \
			WARN("Out of bounds %s: %s", name, str); \
			return -ERANGE; \
		} \
		if (*endptr != '\0')  \
			WARN("Trailing chars for %s %s",  \
				name, str); \
	} while(0)


	while ((c = getopt(argc, argv, "a:b:c:u:g:de:l:tThvi:o:")) != -1) {
		switch (c) {
			case 'a':
				ret = add_address(conf, 
						optarg, strlen(optarg));
				if (ret)
					return ret;
				break;
			case 'b':
				conf->bcast = strdup(optarg);
				if (!conf->bcast) {
					WARN("Out of memory (broadcast addr)");
					return -ENOMEM;
				}
				break;
			case 'c':
				g_chrootpath = optarg;
				break;
			case 'u':
				str2id(g_uid, "uid", optarg);
				break;
			case 'g':
				str2id(g_gid, "gid", optarg);
				break;			
			case 'd':
				g_daemonize = 1;
				break;
			case 'e':
				g_envline = strdup(optarg);
				if (!g_envline) {
					WARN("Could not allocate env line");
					return -ENOMEM;
				}
				break;
			case 'l':
				conf->lback = strdup(optarg);
				if (!conf->lback) {
					WARN("Out of memory (loopback addr)");
					return -ENOMEM;
				}
				break;
			case 't':
				g_vlogin = 1;
				break;
			case 'T':
				g_vlogin_post = 1;
				break;
			case 'v':
				print_version(basename(argv[0]));
				exit(EXIT_SUCCESS);
			case 'h':
				print_help(basename(argv[0]));
				exit(EXIT_SUCCESS);
			case 'i':
				g_stdin_path = optarg;
				break;
			case 'o':
				g_stdout_path = optarg;
				break;
				
			default:
				return -EINVAL;
				break;
		}
	}
	return 0;
}

#define RANDOM_DEVICE "/dev/urandom"

static inline int
get_cookie(void)
{
	char packed_cookie[COOKIE_LEN/2];
	int f;
	ssize_t readlen;
	char *ptr;

	f = open(RANDOM_DEVICE, O_RDONLY);
	if (f == -1) {
		WARN_ERRNO("Failed to open random device");
		return -1;
	}
	readlen = read(f, &packed_cookie, COOKIE_LEN/2);
	if (readlen < 0) {
		WARN_ERRNO("Failed to read random device");
		return -1;
	}
	if (readlen < COOKIE_LEN/2) {
		WARN("Did not get a full cookie, still hungry");
		return -1;
	}

	ptr = packed_cookie;

	while (readlen--) 
		printf("%02x", (*ptr++) & 0xff);

	putchar('\n');

	return 0;
}	

int main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	const char *confroot;
	char *tmp = NULL;
	action_t action;
	struct vserver_conf *conf = NULL;

	g_cmdline = argv;

	if (set_privs(PRIVS_OFF)) {
		WARN("Could not drop privileges");
		return EXIT_FAILURE;
	}

	conf = vserver_conf_new();
	if (!conf) {
		WARN("So soon out of memory ?");
		return EXIT_FAILURE;
	}

	if (get_options(conf, argc, argv)) {
		WARN("Failed to parse options");
		return EXIT_FAILURE;
	}
	argc -= optind;
	argv += optind;
	if (argc < 2) {
		WARN("I want an action and a conf root");
		return EXIT_FAILURE;
	}

	conf->name = strdup(argv[0]);
	if (!conf->name)
		goto out_free;

	action = get_action(argv[1]);

	if (asprintf(&tmp, "%s/%s", _CONF_BASE, argv[0]) == -1 ) {
		WARN("So soon out of memory ?");
		goto out_free;
	}
	confroot = tmp;

	/* Read config */
	switch (action) {
		case ActionStart:
		case ActionSetup:
#ifdef TESTING
		case ActionMount:
		case ActionUmount:
#endif
			ret = read_config(confroot, conf);
			if (ret) {
				WARN("Failed to read configuration");
				goto out_free;
			}
			break;
		case ActionEnter:
			ret = read_nsopts(confroot, conf);
			if (ret) {
				WARN("Failed to read nsopts");
				goto out_free;
			}
			conf->cmd = strdup("/bin/sh");
			if (!conf->cmd) {
				ret = -1;
				WARN("Out of memory - "
					"missing about 8 bytes, tough luck");
				goto out_free;
			}
			/* Fall through :) */	
		case ActionStop:
			ret = read_context(confroot, conf);
			if (ret) {
				WARN("Failed to read the context");
				goto out_free;
			}
			if (!conf->xid) {
				WARN("Abusing vsctl to run commands in "
				      "context 0 is verboten");
				ret = EXIT_FAILURE;
				goto out_free;
			}
			break;
		case ActionEndSetup:
			break;
		case ActionCookie:
			return get_cookie();
			break;
		default:
			ret = EXIT_FAILURE;
			WARN("Invalid action: %s", argv[1]);
			goto out_free;
			break;
	}

	if (set_privs(PRIVS_ON)) {
		WARN("Could not re-engage privileges");
		ret = EXIT_FAILURE;
		goto out_free;
	}

	/* If we're using a PID namespace, we should not daemonize 
	 * outside of the namespace, but rather inside
	 */
	if (g_daemonize && !(conf->nsopts & CLIP_VSERVER_PIDNS)) {
		ret = clip_daemonize();
		if (ret) {
			WARN("Could not daemonize self");
			goto out_free;
		}
	}
	if (g_stdin_path || g_stdout_path) {
		if (clip_reset_fds(g_stdin_path, g_stdout_path) == -1) {
			WARN("Could not reset file descriptors");
			goto out_free;
		}
	}

	/* Execute */
	switch (action) {
#ifdef TESTING
		case ActionMount:
			ret = do_mounts(conf->mounts);
			break;
		case ActionUmount:
			ret = do_umounts(conf->mounts, 1);
			break;
#endif
		case ActionStart:
			ret = start_config(conf, 0);
			break;
		case ActionSetup:
			ret = start_config(conf, 1);
			break;
		case ActionEndSetup:
			ret = sock_connect(conf->name);
			break;
		case ActionEnter:
			if (argc > 2) 
				ret = enter_config(conf, argv+2);
			else 
				ret = enter_config(conf, NULL);
			break;
		case ActionStop:
			ret = stop_config(conf);
			break;
		default:
			break;
	}
	if (ret)
		WARN("Command failed");
			
	/* Fallthrough */
out_free:
	if (tmp)
		free(tmp);
	if (conf)
		vserver_conf_free(conf);
	if (ret)
		WARN("Execution aborted");
	return ret;
}
