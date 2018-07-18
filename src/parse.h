// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  parse.h - vsctl parse functions
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2014 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#ifndef _PARSE_H
#define _PARSE_H

/**************************************************************/
/*                       parse_stub.c                         */
/**************************************************************/

typedef int (*interp_ptr)(const char *, size_t, void *);

int parse(const char *, size_t len, int sep, interp_ptr, void *);

/**************************************************************/
/*                       parse.c                              */
/**************************************************************/

int read_file(const char *, char **, size_t *, int);

int chomp(char *, size_t);
int chomp_sep(char *, size_t);

int read_token(const char **, const char **, size_t *readlen, size_t maxlen);

#endif /* _PARSE_H */
