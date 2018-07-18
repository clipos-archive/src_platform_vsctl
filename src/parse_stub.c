// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  parse_stub.c - basic string parser, shared by vsctl and nsmount
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2012 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "common.h"
#include "parse.h"

int 
parse(const char *str, size_t len, int sep, interp_ptr interp, void *res)
{
	const char *cur, *ptr;
	size_t curlen;
	int ret = 0;

	cur = str;
	while ((size_t) (cur - str) < len && (ptr = strchr(cur, sep))) {
		curlen = ptr - cur;
		if (!curlen) {
			cur = ptr + 1;
			continue;
		}
		ret = (*interp)(cur, curlen, res);
		if (ret) {
			WARN("Interpreter error : %s", strerror(-ret));
			return ret;
		}
		cur = ptr + 1;
	}
	curlen = strlen(cur);
	if (curlen) {
		ret = (*interp)(cur, curlen, res);
		if (ret) 
			WARN("Interpreter error : %s", strerror(-ret));
	}

	return ret;
}
	
