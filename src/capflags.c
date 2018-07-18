// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  capflags.c - vsctl capabilities and flags parsers
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2012 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <linux/capability.h>
#ifndef CAP_CONTEXT
#define CAP_CONTEXT 34
#endif
#include <uapi/vserver/context.h>
#include <uapi/vserver/network.h>
#include <errno.h>
#include <clip/clip-vserver.h>

#include "vsctl.h"
typedef unsigned int xid_t;
typedef unsigned int nid_t;

/*************************************************************/
/*                     Generic flags map                     */
/*************************************************************/

typedef struct {
	size_t len;
	const char *name;
	uint_least64_t val;
} flag_t;

static inline int 
find_flag(const char *str, size_t len, const flag_t *map, uint_least64_t *dest)
{
	int i = 0;
	const flag_t *cur;

	do {
		cur = map + i;
		if (cur->len == len && !strncasecmp(cur->name, str, len-1))
			goto found;
		++i;
	} while (cur->len);

	WARN("Unrecognized pattern: %.*s", (int) len, str);
	return -1;
	
found:
	*dest = cur->val;
	return 0;
}

/*************************************************************/
/*                     Internal interpreters                 */
/*************************************************************/


		/****************/
		/*  POSIX caps  */
		/****************/

#define CAP_TO_FLAG(cap) { sizeof(#cap) - 1, #cap, cap }
#define NAME_TO_FLAG(name, flag) { sizeof(name) - 1, name, flag }

static const flag_t g_pcaps_map[] = {
	CAP_TO_FLAG(CAP_CHOWN),
	CAP_TO_FLAG(CAP_DAC_OVERRIDE),
	CAP_TO_FLAG(CAP_DAC_READ_SEARCH),
	CAP_TO_FLAG(CAP_FOWNER),
	CAP_TO_FLAG(CAP_FSETID),
	CAP_TO_FLAG(CAP_KILL),
	CAP_TO_FLAG(CAP_SETGID),
	CAP_TO_FLAG(CAP_SETUID),
	CAP_TO_FLAG(CAP_SETPCAP),
	CAP_TO_FLAG(CAP_LINUX_IMMUTABLE),
	CAP_TO_FLAG(CAP_NET_BIND_SERVICE),
	CAP_TO_FLAG(CAP_NET_BROADCAST),
	CAP_TO_FLAG(CAP_NET_ADMIN),
	CAP_TO_FLAG(CAP_NET_RAW),
	CAP_TO_FLAG(CAP_IPC_LOCK),
	CAP_TO_FLAG(CAP_IPC_OWNER),
	CAP_TO_FLAG(CAP_SYS_MODULE),
	CAP_TO_FLAG(CAP_SYS_RAWIO),
	CAP_TO_FLAG(CAP_SYS_CHROOT),
	CAP_TO_FLAG(CAP_SYS_PTRACE),
	CAP_TO_FLAG(CAP_SYS_PACCT),
	CAP_TO_FLAG(CAP_SYS_ADMIN),
	CAP_TO_FLAG(CAP_SYS_BOOT),
	CAP_TO_FLAG(CAP_SYS_NICE),
	CAP_TO_FLAG(CAP_SYS_RESOURCE),
	CAP_TO_FLAG(CAP_SYS_TIME),
	CAP_TO_FLAG(CAP_SYS_TTY_CONFIG),
	CAP_TO_FLAG(CAP_MKNOD),
	CAP_TO_FLAG(CAP_LEASE),
	CAP_TO_FLAG(CAP_AUDIT_WRITE),
	CAP_TO_FLAG(CAP_AUDIT_CONTROL),
	CAP_TO_FLAG(CAP_SETFCAP),
	CAP_TO_FLAG(CAP_MAC_OVERRIDE),
	CAP_TO_FLAG(CAP_MAC_ADMIN),
	CAP_TO_FLAG(CAP_CONTEXT),	
	{ 0, NULL, 0 }
};	

static int
_pcaps_interp(const char *str, size_t len, void *res)
{
	uint_least64_t cap;
	uint_least64_t *ret = res;	
	if (find_flag(str, len, g_pcaps_map, &cap) == -1)
		return -EINVAL;
	*ret |= 1UL << cap;
	return 0;	
}

		/******************/
		/*  context caps  */
		/******************/

static const flag_t g_ccaps_map[] = {
	NAME_TO_FLAG("set_utsname", VXC_SET_UTSNAME),
	NAME_TO_FLAG("set_rlimit", VXC_SET_RLIMIT),
	NAME_TO_FLAG("fs_security", VXC_FS_SECURITY),
	NAME_TO_FLAG("syslog", VXC_SYSLOG),
	NAME_TO_FLAG("secure_mount", VXC_SECURE_MOUNT),
	NAME_TO_FLAG("binary_mount", VXC_BINARY_MOUNT),
	NAME_TO_FLAG("quota_ctl", VXC_QUOTA_CTL),
	NAME_TO_FLAG("kthread", VXC_KTHREAD),	
#ifndef COMPAT
	NAME_TO_FLAG("admin_mapper", VXC_ADMIN_MAPPER),
	NAME_TO_FLAG("admin_cloop", VXC_ADMIN_CLOOP),	
#endif
	{ 0, NULL, 0 }
};

		
static int
_ccaps_interp(const char *str, size_t len, void *res)
{
	uint_least64_t cap;
	uint_least64_t *ret = res;	
	if(find_flag(str, len, g_ccaps_map, &cap) == -1)
		return -EINVAL;
	*ret |= cap;
	return 0;	
}

		/*******************/
		/*  context flags  */
		/*******************/
		
static const flag_t g_cflags_map[] = {
	NAME_TO_FLAG("sched", VXF_INFO_SCHED),
	NAME_TO_FLAG("nproc", VXF_INFO_NPROC),
	NAME_TO_FLAG("private", VXF_INFO_PRIVATE),
	NAME_TO_FLAG("fakeinit", VXF_INFO_INIT),
	NAME_TO_FLAG("hideinfo", VXF_INFO_HIDE),
	NAME_TO_FLAG("ulimit", VXF_INFO_ULIMIT),
	NAME_TO_FLAG("namespace", VXF_INFO_NSPACE),
	NAME_TO_FLAG("sched_hard", VXF_SCHED_HARD),
	NAME_TO_FLAG("sched_prio", VXF_SCHED_PRIO),
	NAME_TO_FLAG("sched_pause", VXF_SCHED_PAUSE),
	NAME_TO_FLAG("virt_mem", VXF_VIRT_MEM),
	NAME_TO_FLAG("virt_uptime", VXF_VIRT_UPTIME),
	NAME_TO_FLAG("virt_cpu", VXF_VIRT_CPU),
	NAME_TO_FLAG("virt_load", VXF_VIRT_LOAD),
	NAME_TO_FLAG("virt_time", VXF_VIRT_TIME),
	NAME_TO_FLAG("hide_mount", VXF_HIDE_MOUNT),
	NAME_TO_FLAG("state_setup", VXF_STATE_SETUP),
	NAME_TO_FLAG("state_init", VXF_STATE_INIT),
	NAME_TO_FLAG("fork_rss", VXF_FORK_RSS),
	NAME_TO_FLAG("prolific", VXF_PROLIFIC),
	NAME_TO_FLAG("igneg_nice", VXF_IGNEG_NICE),

#ifndef COMPAT
	NAME_TO_FLAG("virt_time", VXF_VIRT_TIME),
	NAME_TO_FLAG("hide_vinfo", VXF_HIDE_VINFO),
	NAME_TO_FLAG("state_admin", VXF_STATE_ADMIN),
	NAME_TO_FLAG("sc_helper", VXF_SC_HELPER),
	NAME_TO_FLAG("reboot_kill", VXF_REBOOT_KILL),
	NAME_TO_FLAG("persistent", VXF_PERSISTENT),
#endif
	{ 0, NULL, 0 }
};

static int
_cflags_interp(const char *str, size_t len, void *res)
{
	uint_least64_t flag;
	uint_least64_t *ret = res;	
	if(find_flag(str, len, g_cflags_map, &flag) == -1)
		return -EINVAL;
	*ret |= flag;
	return 0;	
}

		/*******************/
		/*  network flags  */
		/*******************/

#ifdef COMPAT
static const flag_t g_nflags_map[] = {
	{ 0, NULL, 0 }
};
#else 
# ifndef NXF_NO_SP
# define NXF_NO_SP	(1ULL << 48)
# endif
static const flag_t g_nflags_map[] = {
	NAME_TO_FLAG("private", NXF_INFO_PRIVATE),
	NAME_TO_FLAG("single_ip", NXF_SINGLE_IP),
	NAME_TO_FLAG("lback_remap", NXF_LBACK_REMAP),
	NAME_TO_FLAG("lback_allow", NXF_LBACK_ALLOW),
	NAME_TO_FLAG("hide_netif", NXF_HIDE_NETIF),
	NAME_TO_FLAG("hide_lback", NXF_HIDE_LBACK),
	NAME_TO_FLAG("state_setup", NXF_STATE_SETUP),
	NAME_TO_FLAG("state_admin", NXF_STATE_ADMIN),
	NAME_TO_FLAG("sc_helper", NXF_SC_HELPER),
	NAME_TO_FLAG("persistent", NXF_PERSISTENT),
	NAME_TO_FLAG("no_sp", NXF_NO_SP),
	{ 0, NULL, 0 }
};
#endif

static int
_nflags_interp(const char *str, size_t len, void *res)
{
	uint_least64_t *ret = res;	
	uint_least64_t flag;
	if (find_flag(str, len, g_nflags_map, &flag) == -1)
		return -EINVAL;
	*ret |= flag;
	return 0;	
}	

		/*******************/
		/*  nsopts flags  */
		/*******************/

static const flag_t g_nsopts_map[] = {
	NAME_TO_FLAG("pid", CLIP_VSERVER_PIDNS),
	NAME_TO_FLAG("net", CLIP_VSERVER_NETNS),
	NAME_TO_FLAG("user", CLIP_VSERVER_USRNS),
	{ 0, NULL, 0 }
};

static int
_nsopts_interp(const char *str, size_t len, void *res)
{
	int *ret = res;	
	uint_least64_t flag;
	if (find_flag(str, len, g_nsopts_map, &flag) == -1)
		return -EINVAL;
	*ret |= (int)flag;
	return 0;	
}	
#undef NAME_TO_FLAG


/*************************************************************/
/*                     External API                          */
/*************************************************************/

int
read_capflags(const char *fname, param_type_t ptype, uint_least64_t *res)
{
	char *str;
	size_t len;
	uint_least64_t val = 0;
	interp_ptr interp;
	int ret;
	int err_noent = 1;

	switch (ptype) {
		case PARAM_POSIX_CAPS:
			interp = _pcaps_interp;
			break;
		case PARAM_CTX_CAPS:
			interp = _ccaps_interp;
			break;
		case PARAM_CTX_FLAGS:
			interp = _cflags_interp;
			break;
		case PARAM_NET_FLAGS:
			interp = _nflags_interp;
			break;
		case PARAM_NS_OPTS:
			interp = _nsopts_interp;
			err_noent = 0;
			break;
		default:
			WARN("unknown param type : %d", ptype);
			return -1;
	}

	if (read_file(fname, &str, &len, err_noent)) {
		if (err_noent)
			return -ENOENT;
		else {
			*res = 0;
			return 0;
		}
	}

	ret = parse(str, len, '\n', interp, &val);
	if (ret)
		goto out_free;

	*res = val;

	/* Fall through */
out_free:
	free(str);
	return ret;
}

