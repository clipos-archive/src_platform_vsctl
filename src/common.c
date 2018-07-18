// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  common.c - vsctl common functions
 *  Copyright (C) 2014 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#include "common.h"

#include <pwd.h>


typedef enum {
	EnvPath = 0,
	EnvHome,
	EnvUser,
	EnvTerm,
	EnvNull,
	EnvMax
} env_field_t;

static int
do_std_envp(char **envp, uid_t uid, const char *name, const char *home) 
{
	const char *term;

	if (uid) {
		envp[EnvPath] = strdup("PATH=/bin:/usr/bin:/usr/local/bin");
	} else {
		envp[EnvPath] = strdup("PATH=/bin:/sbin:/usr/bin:/usr/sbin");
	}

	if (!envp[EnvPath])
		return -1;

	if (home) {
		if (asprintf(&envp[EnvHome],
				"HOME=%s", home) == -1)
			return -1;
	} else {
		if (uid) {
			envp[EnvHome] = strdup("HOME=/home/user");
		} else {
			envp[EnvHome] = strdup("HOME=/root");
		}
		if (!envp[EnvHome])
			return -1;
	}

	if (asprintf(&envp[EnvUser],
			"USER=%s", name) == -1)
		return -1;

	term = getenv("TERM");
	if (term) {
		if (asprintf(&envp[EnvTerm], "TERM=%s", term) == -1)
			return -1;
	} else {
		envp[EnvTerm] = NULL;
	}

	envp[EnvNull] = NULL;
	return 0;
}

void
free_envp(char **envp)
{
	unsigned int i;
	for (i = 0; envp[i]; i++) 
		free(envp[i]);
	free(envp);
}

char ** 
setup_envp(uid_t uid, const char *name, const char *home) 
{
	char **envp = NULL;

	envp = calloc(EnvMax, sizeof(char *));
	if (!envp)
		return NULL;

	if (!do_std_envp(envp, uid, name, home))
		return envp;
	else {
		free_envp(envp);
		return NULL;
	}
}

char **
setup_custom_envp(uid_t uid, const char *name, const char *home, char *envline)
{
	char *str, *ptr;
	char **envp;
	unsigned int count = 1, i;
	
	ptr = str = envline;

	while (*ptr != '\0') {
		if (*ptr++ == '%')
			count++;
	}

	count += EnvMax;

	envp = calloc(count, sizeof(char *));
	if (!envp) {
		WARN("Out of memory");
		return NULL;
	}

	if (do_std_envp(envp, uid, name, home))
		goto out_free;

	i = EnvNull; /* Start of custom env vars */
	while ((ptr = strsep(&str, "%")) != NULL) {
		if (i >= count) {
			WARN("Something wrong with envline parsing : "
					"(%d >= %d)", i, count);
			goto out_free;
		}
		envp[i] = strdup(ptr);
		if (!envp[i]) {
			WARN("Out of memory");
			goto out_free;
		}
		i++;
	}

	if (i >= count) {
		WARN("Envline parsing - too many vars (%d >= %d)", i, count);
		goto out_free;
	}
	envp[i] = NULL;
	return envp;

out_free:
	free_envp(envp);
	return NULL;
}


