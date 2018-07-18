// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  mount_parse.h - vsctl/nsmount common code for parsing
 *  mount flags.
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2012 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#ifndef _MOUNT_PARSE_H
#define _MOUNT_PARSE_H

#ifndef MS_REC
#define MS_REC 0x4000
#endif 
/* custom util-linux defines */
#define MS_NOAUTO	0x80000000
#define MS_USERS	0x40000000
#define MS_USER		0x20000000
#define MS_OWNER	0x10000000
#define MS_GROUP	0x08000000
#define MS_LOOP		0x00010000

/* custom clip defines */
#define MS_NOSYMFOLLOW	256
#define MS_NOLOCK	512
#define MS_TRACE	(1<<26)

/* NB: define CANONICAL for 'canonical' mount extra_opts */
  
/*************************************************************/
/*                  Mount flags & opts parsing               */
/*************************************************************/

typedef struct {
	size_t len;
	const char *name;
	int invert;
	unsigned long val;
} mountflag_t; 

#define LEN_NAME(name) sizeof(name) - 1, name

/* List is plundered from util-linux/mount.c, 
 * without the more baroque ones. */
static const mountflag_t g_flag_map[] = {
  { LEN_NAME("defaults"),	0, 0		},
  { LEN_NAME("ro"),	 	0, MS_RDONLY	},
  { LEN_NAME("rw"),	 	1, MS_RDONLY	},
  { LEN_NAME("exec"),	 	1, MS_NOEXEC	},
  { LEN_NAME("noexec"),		0, MS_NOEXEC	},
  { LEN_NAME("suid"),		1, MS_NOSUID	},
  { LEN_NAME("nosuid"),		0, MS_NOSUID	},
  { LEN_NAME("dev"),		1, MS_NODEV	},
  { LEN_NAME("nodev"),		0, MS_NODEV	},
  { LEN_NAME("sync"),		0, MS_SYNCHRONOUS},
  { LEN_NAME("async"),		1, MS_SYNCHRONOUS},
  { LEN_NAME("remount"),  	0, MS_REMOUNT},
  { LEN_NAME("bind"),		0, MS_BIND   },
  { LEN_NAME("rbind"),		0, MS_BIND|MS_REC }, 
  { LEN_NAME("auto"),		1, MS_NOAUTO	},
  { LEN_NAME("noauto"),		0, MS_NOAUTO	},
  { LEN_NAME("users"),		0, MS_USERS	},
  { LEN_NAME("nousers"),	0, MS_USERS	},
  /* NB: next few do not make much sense.
   * Maybe we should remove them / warn caller */
  { LEN_NAME("user"),		0, MS_USER	},
  { LEN_NAME("nouser"),		1, MS_USER	},
  { LEN_NAME("owner"),		0, MS_OWNER  },	
  { LEN_NAME("noowner"),	1, MS_OWNER  },	
  { LEN_NAME("group"),		0, MS_GROUP  },	
  { LEN_NAME("nogroup"),	1, MS_GROUP  },	
  { LEN_NAME("mand"),		0, MS_MANDLOCK },	
  { LEN_NAME("nomand"),		1, MS_MANDLOCK },	
  { LEN_NAME("loop"),		0, MS_LOOP	},	
  { LEN_NAME("atime"),		1, MS_NOATIME },	
  { LEN_NAME("noatime"),	0, MS_NOATIME },	
  { LEN_NAME("diratime"),	1, MS_NODIRATIME },	
  { LEN_NAME("nodiratime"), 	0, MS_NODIRATIME },
  { LEN_NAME("symfollow"), 	1, MS_NOSYMFOLLOW },
  { LEN_NAME("nosymfollow"), 	0, MS_NOSYMFOLLOW },
  { LEN_NAME("lock"), 		1, MS_NOLOCK },
  { LEN_NAME("nolock"), 	0, MS_NOLOCK },
  { LEN_NAME("trace"), 		0, MS_TRACE },
  { LEN_NAME("notrace"),	1, MS_TRACE },
  { 0, NULL, 0 , 0 }
};

struct finterp_arg {
	unsigned long flags; 	/* actual mount flags */
	char *data;    		/* extra opts */
	size_t	len;	     	/* allocated length of extra opts */
};

static inline int 
add_extraopt(const char *str, size_t len, struct finterp_arg *arg)
{
	char *tmp;
	if (!arg->len) { /* first alloc, we don't need a ',' */
		tmp = malloc(len + 1); 
		if (!tmp)
			return -ENOMEM;
		arg->data = tmp;
		memcpy(arg->data, str, len); 
		arg->data[len] = '\0';
		arg->len = len;
	} else {
		/* +1 for ',' and '\0' */
		tmp = realloc(arg->data, arg->len + len + 2); 
		if (!tmp)
			return -ENOMEM;
		arg->data = tmp;
		arg->data[arg->len] = ',';
		memcpy(arg->data + arg->len + 1, str, len);
		arg->len += len + 1;
		arg->data[arg->len] = '\0';
	}
	return 0;
}

static int
_mountflags_interp(const char *str, size_t len, void *res)
{
	const mountflag_t *cur;
	struct finterp_arg *arg = res;
	int i = 0;
	
	DEBUG2("parsing %.*s\n", len, str);
	do {
		cur = &g_flag_map[i];
		if (cur->len == len && !strncmp(cur->name, str, len))
			goto found_flag;
		++i;
	} while (cur->len);

	/* Not a flag, add to extra opts */
	if (add_extraopt(str, len, arg))
		return -ENOMEM;
	DEBUG2("Added to extra_opts, now %s\n", arg->data);
	return 0;

found_flag:
	DEBUG2("Found flag %s\n", cur->name);
	if (cur->invert) 
		arg->flags &= ~(cur->val);
	else {
		arg->flags |= cur->val;
#ifdef CANONICAL
		/* ro/rw must come first */
		if (cur->val && cur->val != MS_RDONLY) 
			if (add_extraopt(cur->name, cur->len, arg))
				return -ENOMEM;
#endif
	}
	return 0;
}

#ifdef CANONICAL
/* Yuck, we need to put "ro" or "rw" at the start of a canonical 
 * mount extra_opts line (once again, shameless plug from util-linux) */
static inline int
fixup_extraopts(struct finterp_arg *arg)
{
	char *orig, *new;
	/* We may or may not need a ',' */
	const size_t len = (arg->len) ? 3 : 2;

	orig = arg->data;
	new = malloc(arg->len + len +1);
	if (!new) {
		/* No point keeping the original in that case */
		free(orig);
		return -ENOMEM;
	}
	/* We skip the ',' if not needed based on len */
	memcpy(new, (arg->flags & MS_RDONLY) ? "ro," : "rw,", len);
	memcpy(new + len, orig, arg->len);
	new[arg->len + len] = '\0';
	arg->data = new;
	arg->len += len;
	free(orig);
	return 0;
}
#else
static inline int
fixup_extraopts(struct finterp_arg *arg)
{
	if (!arg->data) {
		arg->data = strdup("");
		if (!arg->data) 
			return -ENOMEM;
		arg->len=0;
	}
	return 0;
}
#endif 

#endif /* _MOUNT_PARSE_H */
