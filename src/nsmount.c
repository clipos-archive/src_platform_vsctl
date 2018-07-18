// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  nsmount.c - nsmount main
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2013 SGDSN/ANSSI
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
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <clip/clip-vserver.h>

#include "common.h"
#include "parse.h"
#include "mount_parse.h"

/* Ah, quick and dirty global variables :) */
static const char *g_src;
static const char *g_dst;
static char *g_type;
static const char *g_mtab;
static char *g_data;
static unsigned long g_flags;
static unsigned long g_xid;

static uid_t g_uid;

#define UNPRIVILEGED_UID 250U
#define UNPRIVILEGED_GID 250U

static inline void
print_help(const char *prog)
{
	printf("%s [-vh]\n", prog);
	printf("%s -u [-m <path>] -x <xid> <mnt>\n", prog);
	printf("%s [-m <path>]-x <xid> <src> <dest> -o <options> "
					"-t <type>[,<type2>,...]\n", prog);
	puts("Options:");
	puts("\t-v : show version and exit");
	puts("\t-h : show help and exit");
	puts("\t-u : umount");
	puts("\t-x <xid> : xid of namespace");
	puts("\t-o <options> : mount options");
	puts("\t-t <type> : mount filesystem type");
	puts("\t-m <path> : use <path> as mtab file (no mtab by default)");
}


/*************************************************************/
/*                      mtab helpers                         */
/*************************************************************/


static inline int
open_and_lock_mtab(int umount_p)
{
	int fd;

	if (umount_p)
		fd = open(g_mtab, O_RDWR|O_NOFOLLOW);
	else
		fd = open(g_mtab, O_WRONLY|O_CREAT|O_APPEND|O_NOFOLLOW, 
					S_IRUSR|S_IWUSR|S_IRGRP);
	
	if (fd == -1) {
		PERROR("open");
		return -1;
	}
	
	/* Lock the mtab file to avoid mangling it on concurrent runs
	 * Unlocking done by update_mtab_{,u}mount.
	 */
	if (lockf(fd, F_LOCK, 0) == -1) {
		PERROR("lockf");
		if (close(fd))
			PERROR("close");
		return -1;
	}

	return fd;
}

static inline int 
_read(int fd, char *buf, size_t len)
{
	ssize_t rlen;
	char *ptr = buf;
	size_t remaining = len;

	for (;;) {
		rlen = read(fd, ptr, remaining);
		if (rlen < 0) {
			if (errno == EINTR)
				continue;
			PERROR("read");
			return -1;
		}
		ptr += rlen;
		remaining -= rlen;
		if (!remaining)
			break;
	}
	return 0;
}

static inline int
_write(int fd, char *buf, size_t len)
{
	ssize_t wlen;
	char *ptr = buf;
	size_t remaining = len;

	for (;;) {
		wlen = write(fd, buf, remaining);
		if (wlen < 0) {
			if (errno == EINTR)
				continue;
			PERROR("write");
			return -1;
		}
		ptr += wlen;
		remaining -= wlen;
		if (!remaining)
			break;
	}
	return 0;
}

/* Drop all privs except the open fd before we touch the mtab, 
 * in case I messed up on the parser...  */
static inline int
drop_privs(void)
{
	if (setgid(UNPRIVILEGED_GID)) {
		PERROR("setgid");
		return -1;
	}
	if (setuid(UNPRIVILEGED_UID)) {
		PERROR("setuid");
		return -1;
	}
	return 0;
}


/*************************************************************/
/*                      mtab update                          */
/*************************************************************/

/* Write out a new mtab line at the end of the file.
 * fd is supposed to be opened with O_APPEND. */
static inline int
update_mtab_mount(int fd, const char *opts)
{
	const char *ptr;
	char *buf;
	size_t len;
	ssize_t wlen;
	int ret = -1;

	ptr = g_src;
	/* The mount's source must not be preceded by a ' ' or '\t' for the 
	 * mtab update at umount time to be reliable (i.e. delete the 
	 * correct line) */
	while (isspace(*ptr))
		ptr++;
	len = strlen(ptr) + strlen(g_dst) + strlen(g_type) + strlen(opts);
	/* +1 x3 for spaces, +1 for \n */
	len += 4;
	buf = malloc(len + 1);
	if (!buf) {
		WARN("Out of memory");
		goto out_unlock;
	}
	wlen = snprintf(buf, len + 1, "%s %s %s %s\n", 
				ptr, g_dst, g_type, opts);
	if (wlen < 0) {
		PERROR("snprintf");
		goto out_free;
	}
	if ((size_t)wlen != len) {
		WARN("snprintf : wrong length");
		goto out_free;
	}

	ret = _write(fd, buf, len);
	/* Fall through */

out_free:
	free(buf);
out_unlock:
	if (lockf(fd, F_ULOCK, 0))
		PERROR("lockf F_ULOCK");
	if (close(fd))
		PERROR("close");
	return ret;
}

#define MTAB_NOTFOUND -2

static inline int
update_mtab_umount(int fd)
{
	char *buf, *dstptr, *end1, *start2, *tmp;
	struct stat stbuf;
	off_t offset;
	
	int ret = -1;
	size_t len = strlen(g_dst);

	/* What we really need to match is " ${g_dst} " */
	char * pattern = malloc(len + 3);
	if (!pattern) {
		WARN("Out of memory");
		goto out_unlock;
	}
	ret = snprintf(pattern, len+3, " %s ", g_dst);
	if (ret < 0) {
		PERROR("snprintf");
		ret = -1;
		goto out_freepat;
	}
	if ((size_t)ret != len+2) {
		WARN("snprintf: wrong length");
		ret = -1;
		goto out_freepat;
	}
	ret = -1;

	if (fstat(fd, &stbuf) == -1) {
		PERROR("fstat");
		goto out_freepat;
	}
	buf = malloc(stbuf.st_size + 1);
	if (!buf) {
		WARN("Out of memory");
		goto out_freepat;
	}

	if (_read(fd, buf, stbuf.st_size)) 
		goto out_freebuf;

	buf[stbuf.st_size] = '\0';

	/* Find last occurence of g_dst */
	/* NB : buf is not expected to start with g_dst, since it has to have 
	 * a matching src first, and its length is >= 1 thus it is ok to start 
	 * at buf+1 */
	dstptr = tmp = buf;
	while ((tmp = strstr(tmp + 1, pattern))) {
		if (isspace(*(tmp - 1)))
			continue; /* We want to match on the mount's 
				   * destination, not on its source. */
		dstptr = tmp;
	}
	if (dstptr == buf) {
		ret = MTAB_NOTFOUND;
		goto out_freebuf;
	}

	/* Find last '\n' before dstptr.
	 * Destroying dstptr is no problem, since it won't be written
	 * out anyway */
	*dstptr = '\0';
	end1 = strrchr(buf, '\n'); /* end1 == NULL ok: g_dst on first line */
	
	/* Find first '\n' after dstptr
	 * dstptr + 1 is ok since strlen(pattern) > 0 */
	start2 = strchr(dstptr + 1, '\n');
	if (!start2) {
		WARN("mtab %s missing a newline", g_mtab);
		goto out_freebuf;
	}

	if (lseek(fd, 0, SEEK_SET) == -1) {
		PERROR("lseek");
		goto out_freebuf;
	}

	if (end1 && end1 != buf && _write(fd, buf, end1 - buf + 1)) 
		goto out_freebuf;	
	/* start2 is at most the penultimate character in buf, since we
	 * added a '\0' at the end... If it is, that means g_dst was the
	 * last line and there is nothing to copy after it. */
	start2++; /* skip newline */
	if (*start2 && _write(fd, start2, stbuf.st_size - (start2 - buf)))
		goto out_freebuf;
		
	/* I'm just too lazy to count :) */
	offset = lseek(fd, 0, SEEK_CUR);
	if (offset == -1) {
		PERROR("lseek SEEK_CUR");
		goto out_freebuf;
	}
	if (ftruncate(fd, offset) == -1) {
		PERROR("ftruncate");
		goto out_freebuf;
	}
	
	ret = 0;
	/* Fall through */

out_freebuf:
	free(buf);
out_freepat:
	free(pattern);
out_unlock:
	if (lockf(fd, F_ULOCK, 0))
		PERROR("lockf F_ULOCK");
	if (close(fd))
		PERROR("close");
	return ret;
}


/*************************************************************/
/*                      mount wrappers                       */
/*************************************************************/


static inline int
do_mount(const char *src, const char *dst, const char *type, 
		unsigned long flags, const char *data)
{
	if(!mount(src, dst, type, flags, data)) {
		return 0;
	}
	if (errno == EROFS) {
		WARN("Read-write mount failed, trying read-only");
		flags |= MS_RDONLY;
		if(!mount(src, dst, type, flags, data)) {
			return 0;
		}
	}
	return -1;
}

static inline int
mount_nomtab(int umount_p)
{
	if (clip_enter_namespace(g_xid))
		return -1;

	if (umount_p) {
		if(umount(g_dst)) {
			PERROR("umount");
			return -1;
		}
		return 0;
	} else {
		char **str = &g_type;
		char *type;
		for (;;) {
			type = strsep(str, ",");
			if (type && *type) { /* Trailing ',' ignored */
				if (do_mount(g_src, g_dst, type, 	
							g_flags, g_data) == 0)
					return 0;
			} else {
				/* We're assuming that if mounting fails for every 
				 * requested type, the errno will be the same for
				 * every failure... If not, we'll only get the last
				 * errno in the error msg. 
				 */
				PERROR("mount");
				return -1;
			}
		}
	}
}

static inline int
mount_mtab_father(const char *opts, int umount_p, pid_t pid, int fd)
{
	int status;
	pid_t wret = waitpid(pid, &status, 0);

	if (wret == -1) {
		PERROR("wait");
		return -1;
	}

	if (wret != pid) {
		WARN("Expected pid %d, got %d", pid, wret);
		return -1;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		WARN("Mount error, mtab was not updated");
		return -1;
	}

	if (drop_privs()) {
		WARN("Could not drop privileges, will not touch mtab");
		if (lockf(fd, F_ULOCK, 0))
			PERROR("lockf F_ULOCK");
		if (close(fd))
			PERROR("close");
		return -1;
	}

	if (umount_p)
		status = update_mtab_umount(fd);
	else 
		status = update_mtab_mount(fd, opts);

	/* Note : we do not return -1 if mtab update fails, 
	 * as the main mount/umount operation has still 
	 * taken place... */
	if (status == MTAB_NOTFOUND) 
		WARN("Could not update mtab : "
				"entry not found");
	else if (status == -1)
		WARN("Could not update mtab");

	return 0;
}

static inline int
mount_mtab(const char *opts, int umount_p)
{
	pid_t pid;
	int fd;

	/* Lock the mtab file before mounting, to make sure the
	 * mount and mtab update are properly sequential */
	fd = open_and_lock_mtab(umount_p);
	if (fd == -1) {
		WARN("Could not open and lock mtab file");
		return -1;
	}
	
	pid = fork();

	switch (pid) {
		case -1:
			PERROR("fork");
			return -1;
		case 0:
			exit(mount_nomtab(umount_p));
		default:
			return mount_mtab_father(opts, umount_p, pid, fd);
	}
}

			
/*************************************************************/
/*                           main                            */
/*************************************************************/

	
int main(int argc, char *argv[])
{
	int opt;
	int ret;
	const char *optstr = NULL;
	char *endptr;
	int umount_p = 0;
	struct finterp_arg farg = {
		.flags = 0,
		.data = NULL,
		.len = 0
	};

	while ((opt = getopt(argc, argv, "uo:t:x:m:hv")) != -1) {
		switch (opt) {
			case 'u':
				umount_p++;
				break;
			case 'o':
				optstr = optarg;
				break;
			case 't':
				g_type = optarg;
				break;
			case 'm':
				g_mtab = optarg;
				break;
			case 'x':
				errno = 0;
				g_xid = strtoul(optarg, &endptr, 10);
				if (errno) {
					WARN("Invalid xid: %s", optarg);
					return EXIT_FAILURE;
				}
				if (g_uid > UINT_MAX) {
					WARN("xid is too big: %s", optarg);
					return EXIT_FAILURE;
				}
				if (*endptr != '\0') 
					WARN("Trailing chars for xid %s", 
						optarg);
				break;
			case 'v':
				print_version(basename(argv[0]));
				return EXIT_SUCCESS;
				break;
			case 'h':
				print_help(basename(argv[0]));
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
	if (!g_xid) {
		WARN("You must pass an xid");
		return EXIT_FAILURE;
	}
	if (umount_p) {
		if (argc < 1) {	
			WARN("Usage: nsmount -x <xid> <mnt>");
			return EXIT_FAILURE;
		}
		g_dst = argv[0];
	} else {
		if (argc < 2) {
			WARN("Usage: nsmount [opts] -x <xid> <src> <dst>");
			return EXIT_FAILURE;
		}
		g_src = argv[0];
		g_dst = argv[1];
	}
	
	if (!g_type)
		g_type = "none";

	if (optstr) {
		ret = parse(optstr, strlen(optstr), ',', 
					_mountflags_interp, &farg);
		if (ret) {
			WARN("Error parsing options");
			return ret;
		}
		ret = fixup_extraopts(&farg);
		if (ret) 
			goto out_free;
		g_data = farg.data;
		g_flags = farg.flags;
	} else {
		g_data = strdup("");
		if (!g_data) {
			WARN("You gotta be kidding me");
			return EXIT_FAILURE;
		}
	}
	
	if (g_mtab)
		ret = mount_mtab(optstr, umount_p);
	else
		ret = mount_nomtab(umount_p);

	/* Fall through */
out_free:
	if (g_data) 
		free(g_data);
	return ret;
}
