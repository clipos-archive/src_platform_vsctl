// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  socket.c - vsctl wait socket
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2012 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include "vsctl.h"

#define COOKIE_ENVVAR "VSCTL_MAGIC_COOKIE"
#define READ_TIMEOUT 500 /* milliseconds, = timeout to read cookie */

static const char *g_cookie;

		/**********************************/
		/*        Socket creation         */
		/**********************************/

/* alloc and return socket name for a jail named @name
 * g_cookie must point to the content of $VSCTL_MAGIC_COOKIE */

static inline char *
_get_sockpath(const char *name)
{
	char *buf;
	size_t len; 
	int written;

	/* + 1 for '.' after jail name, -1 for '\0' in sizeof */
	len = strlen(name) + sizeof("/var/run/vsctl.");
	/* + 8 for cookie part */
	buf = malloc(len + 9);
	
	if (!buf) {
		errno = -ENOMEM;
		return NULL;
	}

	/* People should care more about the retval of *printf... */
	written = snprintf(buf, len+1, "/var/run/vsctl.%s.", name);
	if (written < 0 || (size_t) written > len) {
		WARN("snprintf error");
		free(buf);
		errno = -EFAULT;
		return NULL;
	}
	memcpy(buf+len, g_cookie, 8);
	buf[len+8] = '\0';
	
	return buf;
}

/* bind socket @s to path @buf */

static inline int
_bind_sock(int s, char *buf)
{
	mode_t omode;
	int ret;
	struct sockaddr_un addr;
	struct stat st;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	omode = umask(177);
	
	if (!stat(buf, &st)) {
		WARN("Socket %s already exists, aborting", buf);
		return -1;
	}
	//(void) unlink(buf);
	(void) strncpy(addr.sun_path, buf, sizeof(addr.sun_path));
		
	ret = bind(s, (struct sockaddr *)&addr, sizeof(addr));

	(void) umask(omode);
	return ret;
}

		/**********************************/
		/*        Socket read             */
		/**********************************/

/* Try to read @len bytes on @s to @buf, with a timeout
 * of READ_TIMEOUT. @s is supposed to be non-blocking */

static inline int
_do_read(int s, char *buf, size_t len)
{
	ssize_t slen;
	int ret;
	struct pollfd spoll = {
		.fd = s,
		.events = POLLIN,
	};
	size_t remaining = len;
	char *ptr = buf;
	int count = 10;
	
	while (count-- > 0) {
		ret = poll(&spoll, 1, READ_TIMEOUT/10);
		if (!ret)
			continue; /* timeout */
		if (ret != 1 || spoll.revents != POLLIN) {
			WARN_ERRNO("poll() failed");
			return -1;
		}
			
		slen = read(s, ptr, remaining);
		if (slen < 0) {
			if (errno == EAGAIN) /* Weird, but possible */
				continue;
			WARN_ERRNO("Failed read cookie");
			return -1;
		}
		/* Are we done ? */
		if ((size_t)slen == remaining)
			return 0;
		/* Not quite yet */
		ptr += slen;
		remaining -= slen;
	} 

	WARN("Could not read a whole cookie, %zu remaining", remaining);
	return -1;
}

/* Set @s to non-blocking mode */

static int
_set_nonblock(int s)
{
	int opts;
	opts = fcntl(s, F_GETFL);
	if (opts < 0) {
		PERROR("fcntl(F_GETFL)");
		return -1;
	}
	opts |= O_NONBLOCK;
	if (fcntl(s, F_SETFL, opts) < 0) {
		PERROR("fcntl(F_SETFL)");
		return -1;
	}
	return 0;
}

/* Try to send a (non-blocking) @ok ack on @s,
 * then close @s regardless of wether the write 
 * succeeded or not. @s is supposed to be non-blocking. */

static void
_ack_and_close(int s, int ok)
{
	char ack = (ok) ? 'Y' : 'N';

	if (write(s, &ack, 1) != 1) 
		PERROR("write");

	close(s);
}

/* Accept a connection on @s, and try to read a full cookie 
 * on it within READ_TIMEOUT. Return 0 if a full cookie was
 * read and matched our cookie, -1 otherwise. */
static int
_ack_connect(int s)
{
	char buf[COOKIE_LEN+1];
	struct sockaddr_un dummy;
	socklen_t len;
	int s_com;
	int ok;

	len = sizeof(dummy);
	s_com = accept(s, (struct sockaddr *)&dummy, &len);
	if (s_com < 0) {
		PERROR("accept");
		return -1;
	}

	if (_set_nonblock(s_com) == -1) {
		WARN("Failed to set com socket non-blocking");
		close(s_com);
		return -1;
	}

	if (_do_read(s_com, buf, COOKIE_LEN) == -1) {
		WARN("Failed to read cookie");
		_ack_and_close(s_com, 0);
		return -1;
	}
	
	if (strncmp(g_cookie, buf, COOKIE_LEN)) {
		WARN("Invalid cookie");
		ok = 0;
	} else {
		ok = 1;
	}

	_ack_and_close(s_com, ok);	
	return (ok) ? 0 : -1;
}

static inline int
_detach(void)
{
	pid_t pid = fork();

	switch (pid) {
		case -1:
			PERROR("fork");
			return -1;
			break;
		case 0:
			return 0;
			break;
		default:
			_exit(0);
			break;
	}
}

		/**********************************/
		/*        Child reaper            */
		/**********************************/

static void
sigchld_handler(int sig)
{
	pid_t pid;
	int status;

	if (sig != SIGCHLD) {
		WARN("Invalid signal %d", sig);
		return;
	}


	for (;;) {
		pid = waitpid(-1, &status, WNOHANG);
		if (!pid) 
			return;
		if (pid < 0 && errno == ECHILD)
			return;
	}

	return;
}

static int
setup_reaper(void)
{
	struct sigaction cld_act;
	char **argv = g_cmdline;

	if (argv && argv[0]) {
		unsigned int i = 1;
		size_t len = strlen(argv[0]);
		memset(argv[0], '\0', len);
		snprintf(argv[0], len + 1, "init");
		while (argv[i]) {
			memset(argv[i], '\0', strlen(argv[i]));
			i++;
		}
	}

	if (prctl(PR_SET_NAME, (unsigned long)"init", 0, 0, 0)) {
		WARN_ERRNO("prctl failed");
		return -1;
	}

	memset(&cld_act, 0, sizeof(cld_act));
	sigemptyset(&(cld_act.sa_mask));
	cld_act.sa_handler = sigchld_handler;
	cld_act.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &cld_act, NULL)) {
		WARN_ERRNO("sigaction failed");
		return -1;
	}

	return 0;
}
		/**********************************/
		/*        External API            */
		/**********************************/

int
sock_prepare(const char *name)
{
	int s; 
	char *buf;

	g_cookie = getenv(COOKIE_ENVVAR);
	if (!g_cookie) {
		WARN("Could not get cookie from environment");
		return -1;
	}

	buf = _get_sockpath(name);
	if (!buf) {
		WARN("Could not allocate memory for socket path");
		return -1;
	}
	
	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		PERROR("socket");
		goto out_free;
	}

	if (_bind_sock(s, buf))
		goto out_close;

	return s;

	/* Fall through */
out_close:
	(void) close(s);
	/* Fall through */
out_free:
	free(buf);
	return -1;
}

	
int
sock_wait(int s, int reaper_p)
{
	int ret = -1;

	if (reaper_p) {
		if (setup_reaper())
			return -1;
	}
	
	if (signal(SIGHUP, SIG_IGN)) {
		PERROR("signal");
		goto out_close;
	}
	if (listen(s, 0)) {
		PERROR("listen");
		goto out_close;
	}

	/* Detach as late as possible, so as not to miss too many error
	 * conditions. We can still miss a failed accept(), though... */
	/* Do not detach if we're expected to be the child reaper of this
	 * context, otherwise we will lose PID 1... */
	if (!reaper_p && _detach()) 
		return -1;

	while (_ack_connect(s))
		/* nuthin */ ;

	ret = 0;

	/* Fall through */
out_close:
	(void) close(s);
	return ret;
}

int
sock_connect(const char *name)
{
	int s;
	struct sockaddr_un addr;
	ssize_t slen;
	char *buf;
	char ack;
	int ret = -1;

	g_cookie = getenv(COOKIE_ENVVAR);
	if (!g_cookie) {
		WARN("Could not get cookie from environment");
		return -1;
	}

	buf = _get_sockpath(name);
	if (!buf) {
		WARN("Could not allocate memory for socket path");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	(void) strncpy(addr.sun_path, buf, sizeof(addr.sun_path));
	free(buf);

	s = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		PERROR("socket");
		return -1;
	}

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		PERROR("connect");
		(void) close(s);
		goto out_close;
	}

	slen = write(s, g_cookie, COOKIE_LEN);
	if (slen < 0) {
		PERROR("write cookie");
		goto out_close;
	}
	if (slen < COOKIE_LEN) {
		WARN("Could not write full cookie");
		goto out_close;
	}
	
	slen = read(s, &ack, 1);
	if (slen < 1) {
		WARN("Could not read ack");
		goto out_close;
	}
	if (ack == 'Y') {
		ret = 0;
	} else {
		WARN("Connection refused by waiter process");
	}

	/* Fall through */
out_close:
	(void) close(s);
	if (!ret)
		(void) unlink(addr.sun_path);
	return ret;
}
