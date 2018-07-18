// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  vsattr.c - vsattr main
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
#include <getopt.h>
#include <limits.h>
#include "common.h"

#include <clip/clip-vserver.h>
#include <linux/vserver/inode.h>

#define OPT_ADMIN	0x1001
#define OPT_WATCH	0x1002
#define OPT_HIDE	0x1004

#define OPT_IUNLINK	0x1010
#define OPT_BARRIER	0x1020

#define OPT_NO_ADMIN	0x2001
#define OPT_NO_WATCH	0x2002
#define OPT_NO_HIDE	0x2004

#define OPT_NO_IUNLINK	0x2010
#define OPT_NO_BARRIER	0x2020

static const struct option g_opts[] = {
	{ "admin",	no_argument,	0,	OPT_ADMIN },
	{ "watch",	no_argument,	0,	OPT_WATCH },
	{ "hide",	no_argument,	0,	OPT_HIDE },
	{ "iunlink",	no_argument,	0,	OPT_IUNLINK },
	{ "barrier",	no_argument,	0,	OPT_BARRIER },
	{ "~admin",	no_argument,	0,	OPT_NO_ADMIN },
	{ "~watch",	no_argument,	0,	OPT_NO_WATCH },
	{ "~hide",	no_argument,	0,	OPT_NO_HIDE },
	{ "~iunlink",	no_argument,	0,	OPT_NO_IUNLINK },
	{ "~barrier",	no_argument,	0,	OPT_NO_BARRIER },
	{ 0, 0, 0, 0 }
};

#define BI_OPT(yes, no, val) \
	case yes:	\
		if (del & val) { \
			WARN("Incompatible options"); \
			return EXIT_FAILURE; \
		} \
		set |= val; \
		break; \
	case no:	\
		if (set & val) { \
			WARN("Incompatible options"); \
			return EXIT_FAILURE; \
		} \
		del |= val; \
		break
			

static inline void
print_help(const char *prog)
{
	const struct option *opt = g_opts;
	printf("%s [-vh] --FLAG1 [--FLAG2...] file1 [file2...]\n", prog);
	puts("Options:");
	puts("\t-v : show version and exit");
	puts("\t-h : show help and exit");
	puts("Flags:");
	while (opt->name) {
		printf("\t%s\n", opt->name);
		opt++;
	}
}

int main(int argc, char *argv[])
{
	int c;
	uint32_t set = 0, del = 0;

	while ((c = getopt_long(argc, argv, "hv", g_opts, 0)) != -1) {
		switch (c) {
			BI_OPT(OPT_ADMIN, OPT_NO_ADMIN, IATTR_ADMIN);
			BI_OPT(OPT_WATCH, OPT_NO_WATCH, IATTR_WATCH);
			BI_OPT(OPT_HIDE, OPT_NO_HIDE, IATTR_HIDE);
			BI_OPT(OPT_IUNLINK, OPT_NO_IUNLINK, IATTR_IXUNLINK);
			BI_OPT(OPT_BARRIER, OPT_NO_BARRIER, IATTR_BARRIER);
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

	if (argc < 1) {
		WARN("Not enough arguments : %d", argc);
		return EXIT_FAILURE;
	}

	for (c = 0; c < argc; c++) {
		if (clip_set_iattr(argv[c], set, del) == -1) {
			WARN("Error setting attributes on %s", argv[c]);
			return EXIT_FAILURE;
		}
	}
			
	return 0;
}
