// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  mounts.c - vsctl mounts utilities
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

#include "vsctl.h"
#include "lists.h"

#include <sys/mount.h>

#include "mount_parse.h"

/*************************************************************/
/*                  fstab line parsing                       */
/*************************************************************/

struct minterp_arg {
	struct mntlst_node *head;
	const char *src_pref;
	size_t src_preflen;
	const char *dst_pref;
	size_t dst_preflen;
};
	
#define get_token_pref(cur,tok,len,dst,maxlen,pref,preflen) do {\
	if (read_token((const char **)&cur, (const char **)&tok, &len, maxlen)) { \
		ret = -EINVAL; \
		WARN("Could not read token from %s", tok); \
		goto out_free; \
	} \
	if (!len) { \
		ret = 0; \
		goto out_free; \
	} \
	dst = malloc(preflen + len + 1);\
	if (!dst) { \
		ret = -ENOMEM; \
		WARN("Could not alloc mem for %.*s", (int) len, cur);	\
		goto out_free; \
	} \
	if (pref) \
		memcpy(dst, pref, preflen); \
	memcpy(dst + preflen, cur, len); \
	dst[preflen + len] = '\0'; \
} while (0)

#define get_token(cur,tok,len,dst,maxlen) do {\
	if (read_token((const char **)&cur, (const char **)&tok, &len, maxlen)) { \
		ret = -EINVAL; \
		WARN("Could not read token from %s", tok); \
		goto out_free; \
	} \
	if (!len) { \
		ret = 0; \
		goto out_free; \
	} \
	dst = strndup(cur, len); \
	if (!dst) { \
		ret = -ENOMEM; \
		WARN("Could no copy token %.*s", (int) len, cur); \
		goto out_free; \
	} \
} while (0)	

static int
_mounts_interp(const char *str, size_t len, void *res)
{
	struct minterp_arg *arg;
	struct mntlst_node *head, *new;
	const char *tok, *cur;
	size_t mlen;
	int ret;
	char *tmp = NULL;
	struct finterp_arg farg = {
		.flags = 0,
		.data = NULL,
		.len = 0
	};
	
	/* Skip comments */
	if (str[0] == '#')
		return 0;

	arg = res;
	head = arg->head;
	new = mntlst_new();
	if (!new)
		return -ENOMEM;	

	tok = str;
	ret = -1;
	get_token_pref(cur, tok, mlen, new->src, len - (tok - str),  
			arg->src_pref, arg->src_preflen);
	get_token_pref(cur, tok, mlen, new->dst, len - (tok - str),
			arg->dst_pref, arg->dst_preflen);
	get_token(cur, tok, mlen, new->type, len - (tok - str));
	get_token(cur, tok, mlen, tmp, len - (tok - str));
	
	DEBUG("Read flags : \"%s\"", tmp);
	ret = parse(tmp, mlen, ',', _mountflags_interp, &farg);
	if (ret) {
		WARN("Error parsing options %s", tmp);
		if (farg.data) free(farg.data);
		goto out_free;
	}
	ret = fixup_extraopts(&farg);
	/* fixup_extraopts frees arg.data in case of failure */
	if (ret)
		goto out_free; 

	new->flags = farg.flags;
	new->extra_opts = farg.data;
	
	mntlst_add(new, head);
	free(tmp);
	return 0;

out_free:
	if (tmp) 
		free(tmp);
	mntlst_free(new);
	return ret;
}

int
read_mounts(const char *fname, struct mntlst_node *head, 
		const char *srcpref, const char *dstpref)
{
	char *str;
	size_t len;
	int ret;

	struct minterp_arg arg;

	arg.head = head;
	arg.src_pref = srcpref;
	arg.src_preflen = (srcpref) ? strlen(srcpref) : 0;
	arg.dst_pref = dstpref;
	arg.dst_preflen = (dstpref) ? strlen(dstpref) : 0;

	ret = read_file(fname, &str, &len, 1);
	if (ret)
		return ret;
	
	ret = parse(str, len, '\n', _mounts_interp, &arg);

	free(str);
	return ret;
}

/*************************************************************/
/*                  mountpoints line parsing                 */
/*************************************************************/

static int
_mountpoint_interp(const char *str, size_t len, void *res)
{
	struct mntlst_node *head, *new;

	/* Skip comments */
	if (str[0] == '#')
		return 0;

	head = res;
	new = mntlst_new();
	if (!new)
		return -ENOMEM;	

	new->dst = strndup(str, len);
	if (!new) {
		free(new);
		return -ENOMEM;
	}
	(void)chomp_sep(new->dst, len);

	mntlst_add(new, head);
	return 0;
}
	
int
read_mountpoints(const char *fname, struct mntlst_node *head)
{
	char *str;
	size_t len;
	int ret;

	ret = read_file(fname, &str, &len, 1);
	if (ret)
		return ret;

	ret = parse(str, len, '\n', _mountpoint_interp, head);

	free(str);
	return ret;
}

/*************************************************************/
/*                  mount syscalls                           */
/*************************************************************/

int
do_mounts(const struct mntlst_node *head)
{
	int errcnt = 0;
	struct mntlst_node *cur;
	list_for_each(cur, head) {
		if (mount(cur->src, cur->dst, cur->type, 
				cur->flags, cur->extra_opts)) {
			WARN_ERRNO("mount %s %s error", cur->src, cur->dst);
			errcnt++;
		} else {
			DEBUG("mounted %s on %s", cur->src, cur->dst);
		}
	}
	return errcnt;
}

static inline int
_umount(const struct mntlst_node *mnt)
{
	const char *ptr = mnt->dst;
	int noerr = 0;

	if (*ptr == '*') {
		ptr++; /* Ok, NULL-terminated */
		noerr = 1;
	}

	if (umount(ptr)) {
		if (!noerr) {
			WARN_ERRNO("umount %s error", ptr);
			return -1;
		}
	} else {
		DEBUG("unmounted %s", ptr);
	}

	return 0;
}

int
do_umounts(const struct mntlst_node *head, int invert)
{
	int errcnt = 0;
	struct mntlst_node *cur;
	if (!invert) {
		list_for_each(cur, head) {
			if (_umount(cur))
				errcnt++;
		}
	} else {
		list_for_each_back(cur, head) {
			if (_umount(cur))
				errcnt++;
		}
	}
	return errcnt;
}
