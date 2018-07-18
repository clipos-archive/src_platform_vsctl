// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  protos.h - vsctl global prototypes
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2014 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#ifndef _PROTOS_H
#define _PROTOS_H

#include "common.h"
#include "parse.h"

/**************************************************************/
/*                       capflags.c                           */
/**************************************************************/

typedef enum {
	PARAM_POSIX_CAPS,
	PARAM_CTX_CAPS,
	PARAM_CTX_FLAGS,
	PARAM_NET_FLAGS,
	PARAM_NS_OPTS,
} param_type_t;

extern int read_capflags(const char *, param_type_t, uint_least64_t *);

/**************************************************************/
/*                       mounts.c                             */
/**************************************************************/
struct mntlst_node;
extern int read_mounts(const char *, struct mntlst_node *, 
		const char *, const char*);
extern int read_mountpoints(const char *, struct mntlst_node *);
extern int do_mounts(const struct mntlst_node *);
extern int do_umounts(const struct mntlst_node *, int);

/**************************************************************/
/*                       conf.c                               */
/**************************************************************/

struct vserver_conf;
extern int read_config(const char *confroot, struct vserver_conf *conf);
extern int read_context(const char *confroot, struct vserver_conf *conf);
extern int read_nsopts(const char *confroot, struct vserver_conf *conf);
extern int start_config(struct vserver_conf *conf, int setup_p);
extern int stop_config(const struct vserver_conf *conf);
extern int enter_config(const struct vserver_conf *conf, char **argv);

/**************************************************************/
/*                       socket.c                             */
/**************************************************************/
extern int sock_prepare(const char *);
extern int sock_wait(int, int);
extern int sock_connect(const char *);

/*************************************************************/
/*                       main.c                              */
/*************************************************************/

/* path to chroot to after entering the jail (default: NULL => no chroot) */
extern const char *g_chrootpath;
/* uid to exec under after entering (default: 0) */
extern uid_t g_uid;
/* gid to exec under after entering (default: 0) */
extern gid_t g_gid;
/* daemonize option (default: no) */
extern int g_daemonize;
/* cookie len (ascii-armored) */
#define COOKIE_LEN 40
/* environment line */
extern char *g_envline;
/* bool: setup a terminal proxy */
extern int g_vlogin;
/* bool: setup a terminal proxy in context */
extern int g_vlogin_post;

/* full command line */
extern char **g_cmdline;

#endif /* _PROTOS_H */
