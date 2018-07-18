// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  common.h - vsctl common protos / macros
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2014 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#ifndef _COMMON_H
#define _COMMON_H

#define _GNU_SOURCE

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define WARN(fmt, args...) \
	fprintf(stderr, "%s:%s(%d) - " fmt"\n", \
				__FILE__, __FUNCTION__, __LINE__, ##args)  
#define WARN_ERRNO(fmt, args...) \
		WARN(fmt": %s", ##args, strerror(errno))

#define PERROR(cmd) WARN_ERRNO(cmd"() failed")

#ifdef DEBUG
#define DEBUG(fmt, args...) \
	fprintf(stdout, "%s:%s(%d): " fmt, \
				__FILE__, __FUNCTION__, __LINE__, ##args)  
#else
#define DEBUG(fmt, args...)
#endif

#ifdef DEBUG2
#define DEBUG2(fmt, args...) DEBUG(fmt, ##args)
#else
#define DEBUG2(fmt, args...)
#endif

#define __UNUSED __attribute__((unused))

#define _TO_STR(var) #var
#define TO_STR(var) _TO_STR(var)

/* Max number of addresses handled for a network context */
#define MAX_ADDRS	4

static inline void
print_version(const char *prog)
{
	printf("%s - Version %s\n", prog, TO_STR(VERSION));
}

extern char **setup_envp(uid_t uid, const char *name, const char *home);

extern char **setup_custom_envp(uid_t uid, 
			const char *name, const char *home, char *envline);

extern void free_envp(char **envp);

#endif /* _COMMON_H */
