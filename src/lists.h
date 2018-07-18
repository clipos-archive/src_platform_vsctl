// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  lists.h - vsctl internal chained list structs
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2012 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#ifndef _LIST_H
#define _LIST_H

#include <stdlib.h>

/* doubly linked list of mounts */
struct mntlst_node {
	struct mntlst_node *next, *prev;
	char *src;
	char *dst;
	char *type;
	unsigned long flags;
	char *extra_opts;
};

#define mntlst_print(node) do {\
	if (node->src) printf("src: %s ", node->src);\
	if (node->dst) printf("dst: %s ", node->dst);\
	if (node->type) printf("type: %s ", node->type);\
	if (node->extra_opts) printf("extra: %s ", node->extra_opts);\
	printf("flags: %lx\n", node->flags);\
} while (0)

static inline void _mntlst_add(struct mntlst_node *_new,
			      struct mntlst_node *prev,
			      struct mntlst_node *next)
{
	next->prev = _new;
	_new->next = next;
	_new->prev = prev;
	prev->next = _new;
}

/* Add before head => add at the end of the circular list */
static inline void 
mntlst_add(struct mntlst_node *_new, struct mntlst_node *head)
{
	_mntlst_add(_new, head->prev, head);
}

static inline void 
_mntlst_del(struct mntlst_node * prev, struct mntlst_node * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void 
mntlst_del(struct mntlst_node *node)
{
	_mntlst_del(node->prev, node->next);
	node->next = NULL;
	node->prev = NULL;
}

#define mntlst_init(ptr) do {\
		(ptr)->next = (ptr);\
		(ptr)->prev = (ptr);\
		(ptr)->src = NULL;\
		(ptr)->dst = NULL;\
		(ptr)->type = NULL;\
		(ptr)->extra_opts = NULL;\
		(ptr)->flags = 0UL;\
} while (0)

static inline struct mntlst_node *
mntlst_new(void)
{
	struct mntlst_node *_new;
	_new = malloc(sizeof(*_new));
	if (!_new)
		return NULL;

	mntlst_init(_new);
	return _new;
}

static inline void 
mntlst_free(struct mntlst_node *node)
{
	if (node->src) free(node->src);
	if (node->dst) free(node->dst);
	if (node->type) free(node->type);
	if (node->extra_opts) free(node->extra_opts);
	free(node);
}

static inline void
mntlst_freeall(struct mntlst_node *head)
{
	struct mntlst_node *cur = head->prev;

	while (cur != head) {
		mntlst_del(cur);
		mntlst_free(cur);
		cur = head->prev;
	}
	mntlst_free(head);
}

#define list_for_each(pos, head) for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_back(pos, head) for (pos = (head)->prev; pos != (head); pos = pos->prev)

static inline void
mntlst_printall(struct mntlst_node *head)
{
	struct mntlst_node *cur;
	list_for_each(cur, head) {
		mntlst_print(cur);
	}
}

#endif /*_LIST_H*/
