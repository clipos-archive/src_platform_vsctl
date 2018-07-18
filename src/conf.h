// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  conf.h - vsctl global vserver config
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2014 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#ifndef _CONF_H
#define _CONF_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "lists.h"

struct vserver_conf {
	char *name;
	char *hostname;
	unsigned long xid;
	int nsopts;

	char *root;
	char *cmd;
	char *ns_setup_cmd;

	uint_least64_t bcaps;
	uint_least64_t ccaps;
	uint_least64_t cflags;
	uint_least64_t nflags;

	char **ipaddrs;
	char **netmasks;
	size_t num_addrs;
	size_t next_addr;

	char *lback;
	char *bcast;

	struct mntlst_node *mounts;
	struct mntlst_node *umounts;
};
	
#define ADDRS_INCREMENT	4U /* Allocation increment for ipaddrs/netmasks */

static inline struct vserver_conf *
vserver_conf_new(void)
{
	struct vserver_conf *_new;

	_new = calloc(1, sizeof(*_new));
	if (!_new)
		return NULL;

	_new->num_addrs = 0;
	_new->next_addr = 0;

	/* init dummies */
	_new->mounts = mntlst_new();
	if (!_new->mounts)
		goto err_free;
	_new->umounts = mntlst_new();
	if (!_new->umounts)
		goto err_freemounts;

	return _new;

err_freemounts:
	mntlst_free(_new->mounts);
	/* Fall through */
err_free:
	free(_new);
	return NULL;
}

static inline void
vserver_conf_free(struct vserver_conf *conf)
{
	unsigned int i;
	if (conf->root)
		free(conf->root);
	if (conf->hostname)
		free(conf->hostname);
	if (conf->cmd)
		free(conf->cmd);
	if (conf->ns_setup_cmd)
		free(conf->ns_setup_cmd);
	for (i = 0; i < conf->num_addrs; i++) {
		if (conf->ipaddrs[i])
			free(conf->ipaddrs[i]);
		if (conf->netmasks[i])
			free(conf->netmasks[i]);
	}
	if (conf->ipaddrs)
		free(conf->ipaddrs);
	if (conf->netmasks)
		free(conf->netmasks);

	if (conf->lback)
		free(conf->lback);
	if (conf->bcast)
		free(conf->bcast);

	if (conf->mounts)
		mntlst_freeall(conf->mounts);
	if (conf->umounts)
		mntlst_freeall(conf->umounts);

	free(conf);
}

static inline void
vserver_conf_print(struct vserver_conf *conf)
{
	int i;
	printf("vserver config for xid %lu:\n", conf->xid);
	printf("bcaps %llx ccaps %llx cflags %llx nflags %llx\n", 
	       (long long unsigned int) conf->bcaps, 
	       (long long unsigned int) conf->ccaps,
	       (long long unsigned int) conf->cflags, 
	       (long long unsigned int) conf->nflags);
	if (conf->hostname) 
		printf("hostname \"%s\"\n", conf->hostname);
	if (conf->root) 
		printf("root \"%s\"\n", conf->root);
	if (conf->cmd) 
		printf("cmd \"%s\"\n", conf->cmd);
	if (conf->ns_setup_cmd) 
		printf("ns_setup_cmd \"%s\"\n", conf->ns_setup_cmd);
	for (i = 0; i < MAX_ADDRS; i++) {
		if (conf->ipaddrs[i])
			printf("ipaddr[%i] \"%s\"\n", i, conf->ipaddrs[i]);
		if (conf->netmasks[i])
			printf("netmask[%i] \"%s\"\n", i, conf->netmasks[i]);
	}
	if (conf->lback)
		printf("loopback: \"%s\"\n", conf->lback);
	if (conf->bcast)
		printf("broadcast: \"%s\"\n", conf->bcast);

	printf("nsopts: 0x%x\n", conf->nsopts);

	puts("Mounts:");
	mntlst_printall(conf->mounts);
	puts("Umounts:");
	mntlst_printall(conf->umounts);
}

extern int 
add_address(struct vserver_conf *conf, const char *str, size_t len);


#endif /*_CONF_H*/
