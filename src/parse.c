// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  parse.c - vsctl basic parsers
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
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "parse.h"

static inline int
_do_read(int f, char **dest, size_t *len)
{
	ssize_t readlen;
	struct stat sbuf;
	char *buf = NULL;
	size_t count;
	
	if (fstat(f, &sbuf)) {
		PERROR("fstat");
		return -1;
	}
	if (sbuf.st_size > SSIZE_MAX) {
		WARN("A file that big ? You must be joking...");
		errno = -E2BIG;
		return -1;
	}
	count = sbuf.st_size;	
	buf = malloc(count + 1);
	if (!buf) {
		errno = -ENOMEM;
		return -1;
	}
	readlen = read(f, buf, count);
	if (readlen < 0)
		goto error;

	if (readlen < sbuf.st_size)
		WARN("Only read %zd bytes, file size was %lu", readlen,
				sbuf.st_size);
	
	buf[readlen] = '\0';
	*dest = buf;
	*len = readlen;

	return 0;

error:
	free(buf);
	return -1;
}

	
int
read_file(const char *fname, char **dest, size_t *len, int err_noent)
{
	int ret, f;

	f = open(fname, O_RDONLY);
	if (f == -1) {
		ret = -errno;
		if (err_noent)
			PERROR("open");
		return ret;
	}
	
	ret = _do_read(f, dest, len);
	if (ret)
		PERROR("_do_read");

	DEBUG("read %u chars in %s", *len, fname);
	(void)close(f);

	/* Do not output a warning here, this is expected
	 * behaviour for many files */
	if (!*len) {
		DEBUG("file %s is empty ?", fname);
	}
	return ret;
}	

/* chop trailing newline and return 1, or return 0 if no newline found */
inline int
chomp (char *str, size_t len)
{
	char *ptr = str;

	while ((size_t)(ptr - str) < len && *ptr) {
		if (*ptr == '\n') {
			*ptr = '\0';
			return 1;
		}
		ptr++;
	}
	return 0;
}

#define IS_SEP(ptr) (*(ptr) == ' ' || *(ptr) == '\t') 
#define IS_SEPOREND(ptr) (IS_SEP(ptr) || *(ptr) == '\n')
#define IS_COMMENT(str) (*(str) == '#')
	
inline int
chomp_sep (char *str, size_t len)
{
	char *ptr = str;

	while ((size_t)(ptr - str) < len && *ptr) {
		if (IS_SEPOREND(ptr)) {
			*ptr = '\0';
			return 1;
		}
		ptr++;
	}
	return 0;
}

static inline int
skip_sep(const char *buf, size_t len, const char **new)
{
	const char *ptr = buf;
	size_t count = 0;
	while (ptr && IS_SEP(ptr) && count < len) {
		ptr++;
		count++;
	}
	*new = ptr;
	return count;
}

int
read_token(const char **dest, const char **tok, size_t *len, size_t maxlen)
{

	const char *ptr; 
	const char *str;

	ptr = *tok;
	if (!ptr) {
		WARN("Called on null pointer");
		return -EFAULT;
	}

	while (((size_t)(ptr - *tok) < maxlen) && *ptr && IS_SEP(ptr)) 
		++ptr;
	
	str = ptr;
	
	while (((size_t)(ptr - *tok) < maxlen) && *ptr && !IS_SEPOREND(ptr))
		++ptr;

	*tok = ptr;
	*dest = str;
	*len = ptr - str;

	return 0;
}
