// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  conf.c - vsctl vserver main functions
 *  Copyright (C) 2007-2008 SGDN/DCSSI
 *  Copyright (C) 2009-2014 SGDSN/ANSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>
#ifndef MS_REC
#define MS_REC 0x4000
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <grp.h>
#include <pwd.h>

#include <clip/clip-vserver.h>
#include <clip/clip.h>

#include "vsctl.h"
#include "conf.h"

#include <stdio.h>


static int
get_cgroup_path(const struct vserver_conf* conf, char** p_cgroup) {
    char cgroup_path[1025] = "/sys/fs/cgroup/cgroup_root/jail_";
    char cgroup_path2[1025];
    int ret = 0;
    int max_src_length=0;
    
    if (conf->name == NULL) {
        WARN("cgroup path building : jail name is NULL");
        *p_cgroup = NULL;
        ret = -1;
        goto end;
    }
        
    max_src_length = 1024-strnlen(conf->name, 1024);
        
    if (max_src_length < 0) {        
        WARN("cgroup path building : the name of the jail is > 1024");
        *p_cgroup = NULL;        
        ret = -1;        
        goto end;
    }
    
    strncat(cgroup_path, conf->name, max_src_length);
    
    if (access (cgroup_path, F_OK) == -1) {
        // WARN("cgroup path building : %s doesn't exist",cgroup_path);        
        *p_cgroup = NULL;
        ret = 0;
        goto end;
    }
    
    if (g_chrootpath == NULL) {        
        goto final_copy;
    }
    
    if (strnlen(cgroup_path,1024) > 1015) {
        WARN("cgroup path building : cgroup path has reached max length (1024)");
        *p_cgroup = NULL;
        ret = -1;
        goto end;
    }
    
    strncpy(cgroup_path2, cgroup_path, 1025);
    
    strncat(cgroup_path2, "/chroot_",9);
    
    max_src_length = strnlen(cgroup_path2, 1024)-strnlen(g_chrootpath, 1024);
    
    if (max_src_length < 0) {
        WARN("cgroup path building : %s :  the name of the chroot is too long",cgroup_path2);
        *p_cgroup = NULL;        
        ret = -1;        
        goto end;
    }
    
    strncat(cgroup_path2, g_chrootpath, max_src_length);
    
    if (access (cgroup_path2, F_OK) == -1) {
        // WARN("cgroup path building : %s doesn't exist, fall back on %s",cgroup_path2, cgroup_path);
        ret = 0;
        goto final_copy;
    }
    
    strncpy(cgroup_path, cgroup_path2,1025);

final_copy :    
    *p_cgroup = strndup(cgroup_path,1024);
    
    if (*p_cgroup == NULL) {
        WARN("can't duplicate the cgroup_path");
        ret = -1;
    } else {            
        ret = 0;
    }
    
end :
    return ret;
}

static int
assign_task_to_cgroup(pid_t pid, char *cgroup)
{
	char *pathname = NULL;
	int ret = 0;
	FILE* file_task = NULL;
	if (!cgroup) {
		WARN("cgroup path is null");
		ret = -1;
		goto err_params;
	}

	if (asprintf(&pathname, "%s/tasks", cgroup) == -1) {
		WARN("Memory allocation failed for pathname %s", cgroup);
		ret = -1;
		goto err_asprintf;
	}

	file_task = fopen(pathname, "w");
	if (file_task == NULL) {
		WARN("fopen fail for  pathname %s", pathname);
		ret = -1;
		goto err_open;
	}

	if (fprintf(file_task, "%lu",(unsigned long)pid) < 0) {
		WARN("fail to put task into cgroup");
		ret = -1;
	}
	fclose(file_task);

err_open:
	free(pathname);
err_asprintf:
err_params:
	return ret;
}


static int
enter_cgroup(const struct vserver_conf* conf) {
    pid_t calling_process_pid = getpid();
    char* cgroup_path=NULL;
    int ret = 0;
    
    if (get_cgroup_path(conf, &cgroup_path)) {
        WARN("Can't get a valid cgroup path");
        ret = -1;
        goto end;
    }
    
    // WARN("Enter cgroup %s",cgroup_path);
    
    if (cgroup_path == NULL) {
        // WARN("Looks like no cgroup is defined for this jail");
        ret = 0;
        goto end;
    }
        
    if (assign_task_to_cgroup(calling_process_pid, cgroup_path)) {
        WARN("Can't assign task %d to cgroup %s", calling_process_pid, cgroup_path);
        ret = -1;
        goto end;
    }    

end:
    if (cgroup_path != NULL)
        free(cgroup_path);
    
    return ret;
}

int 
add_address(struct vserver_conf *conf, const char *str, size_t len)
{
	const char *ptr;
	char *tmp1, *tmp2;

	if (conf->next_addr == conf->num_addrs) {
		/* More space needed */
		char **tmp;

		conf->num_addrs += ADDRS_INCREMENT;
		tmp = realloc(conf->ipaddrs, 
					conf->num_addrs * sizeof(char *));
		if (!tmp) {
			WARN("Out of memory - too many addresses");
			return -ENOMEM;
		}
		conf->ipaddrs = tmp;

		tmp = realloc(conf->netmasks, 
					conf->num_addrs * sizeof(char *));
		if (!tmp) {
			WARN("Out of memory - too many addresses");
			return -ENOMEM;
		}
		conf->netmasks = tmp;
	}

	/* Our strnchr */
	ptr = str;
	while ((size_t)(ptr - str) < len) {
		if (*ptr == '/')
			goto found;
		ptr++;
	}
	WARN("Could not find '/' in %.*s", (int) len, str);
	return -1;

found:
	tmp1 = strndup(str, (size_t)(ptr - str));
	if (!tmp1) {
		WARN("Out of memory");
		return -ENOMEM;
	}

	tmp2 = strndup(ptr + 1, len - (ptr - str + 1));
	if (!tmp2) {
		WARN("Out of memory");
		free(tmp1);
		return -ENOMEM;
	}
	(void)chomp_sep(tmp2, len - (ptr - str + 1));

	conf->ipaddrs[conf->next_addr] = tmp1;
	conf->netmasks[conf->next_addr] = tmp2;
	conf->next_addr++;

	return 0;
}

/* Address parser callback */
static int
read_addr_cb(const char *str, size_t len, void *arg)
{
	struct vserver_conf *conf = arg;
	return add_address(conf, str, len);
}

static inline int 
read_addr(struct vserver_conf *conf)
{
	char *str;
	size_t len;
	int ret;

	if (read_file("addr", &str, &len, 1)) 
		return -ENOENT;

	ret = parse(str, len, '\n', read_addr_cb, conf);
	if (ret) {
		free(str);
		WARN("Failed to parse address(es)");
		return ret;
	}
	return 0;
}

static inline int
do_read_context(struct vserver_conf *conf)
{
	char *str, *endptr;
	unsigned long xid;
	size_t len;
	int ret = 0;

	if (read_file("context", &str, &len, 1))
		return -ENOENT;

	if (!len) {
		WARN("Empty context file ?");
		ret = -EINVAL;
		goto out_free;
	}
	(void)chomp_sep(str, len);

	errno = 0;
	xid = strtoul(str, &endptr, 0);
	if (errno) {
		ret = errno;
		goto out_free;
	}
	if (*endptr != '\0')
		WARN("Trailing chars in context : \"%s\"", endptr);

	conf->xid = xid;

	/* Fall through */
out_free:
	free(str);
	return ret;
}

static inline int
read_one(const char *fname, char **target, int err_noent)
{
	size_t len;
	char *str;

	if (read_file(fname, &str, &len, err_noent)) {
		if (err_noent)
			WARN("Could not read file %s", fname);
		return -1;
	}
	if (!len) {
		WARN("Empty %s file ?", fname);
		return -1;
	}
	(void)chomp(str, len);

	*target = str;
	return 0;
}

static int
read_mountsdir(const char *dirname, struct mntlst_node *head,
			const char *srcpref, const char *dstpref)
{
	char *fname = NULL;
	int ret = -1;
	struct dirent **namelist;
	int n, i;

	n = scandir(dirname, &namelist, NULL, alphasort);
	i = n;
	if (i < 0) {
		if (errno == ENOENT) {
			ret = 0;
		} else {
			WARN("Failed to scandir %s : %s", dirname, strerror(errno));
		}
		goto err;
	} else {
		while (i--) {
			if (namelist[i]->d_name[0] == '.')
				continue; /* skip ., .., and hidden files */
			if (asprintf(&fname, "%s/%s", dirname, namelist[i]->d_name) == -1) {
				WARN("Out of memory allocating filename");
				goto out;
			}
			if (read_mounts(fname, head, srcpref, dstpref)) {
				WARN("Failed to read %s", fname);
				free(fname);
				goto out;
			}
			free(fname);
		}
	}

	ret = 0;
	/* Fall through */
out:
	while (n--) {
		free(namelist[n]);
	}
	free(namelist);
err:
	return ret;
}

#define WARN_IFF_NOENT(ret, fname) do { \
	if (ret == -ENOENT) { \
		WARN("No %s file", fname); \
	} else { \
		WARN("Failed to parse %s file", fname); \
		goto out; \
	} \
} while (0)


int
read_config(const char *confroot, struct vserver_conf *conf)
{
	int ret;
	uint_least64_t tmp;

	ret = chdir(confroot);
	if (ret) {
		PERROR("chdir");
		return -1;
	}

	ret = do_read_context(conf);
	if (ret) {
		WARN("Could not read jail context");
		goto out;
	}

	ret = read_one("root", &conf->root, 1);
	if (ret) {
		WARN("Could not read jail root");
		goto out;
	}

	ret = read_one("cmd", &conf->cmd, 1);
	if (ret) {
		WARN("Could not read jail command");
		goto out;
	}

	(void)read_one("ns_setup_cmd", &conf->ns_setup_cmd, 0);
	(void)read_one("hostname", &conf->hostname, 0);

	/* Addresses passed on the command line override any addresses
	 * defined in the conf, instead of just being added to them.
	 */
	if (!conf->num_addrs) {
		ret = read_addr(conf);
		if (ret) {
			WARN("Could not read addr: %s", strerror(-ret));
			goto out;
		}
	}
	if (!conf->bcast)
		(void)read_one("bcast", &conf->bcast, 0);
	if (!conf->lback)
		(void)read_one("lback", &conf->lback, 0);

	ret = read_capflags("bcaps", PARAM_POSIX_CAPS, &conf->bcaps);
	if (ret)
		WARN_IFF_NOENT(ret, "bcaps");
	ret = read_capflags("ccaps", PARAM_CTX_CAPS, &conf->ccaps);
	if (ret)
		WARN_IFF_NOENT(ret, "ccaps");
	ret = read_capflags("cflags", PARAM_CTX_FLAGS, &conf->cflags);
	if (ret)
		WARN_IFF_NOENT(ret, "cflags");
	ret = read_capflags("nflags", PARAM_NET_FLAGS, &conf->nflags);
	if (ret)
		WARN_IFF_NOENT(ret, "nflags");

	ret = read_capflags("nsopts", PARAM_NS_OPTS, &tmp);
	if (ret)
		WARN_IFF_NOENT(ret, "nsopts");

	conf->nsopts = (int)tmp;

	ret = read_mounts("fstab.internal", conf->mounts, 
				conf->root, conf->root);
	if (ret)
		WARN_IFF_NOENT(ret, "fstab.internal");
	ret = read_mountsdir("fstab.internal.d", conf->mounts,
				conf->root, conf->root);
	if (ret)
		WARN("Failed to read fstab.internal.d");
	

	ret = read_mounts("fstab.external", conf->mounts, NULL, conf->root);
	if (ret)
		WARN_IFF_NOENT(ret, "fstab.external");
	ret = read_mountsdir("fstab.external.d", conf->mounts,
				NULL, conf->root);
	if (ret)
		WARN("Failed to read fstab.external.d");

	ret = read_mountpoints("nscleanup", conf->umounts);
	if (ret)
		WARN_IFF_NOENT(ret, "nscleanup");

out:
	return ret;
}

int
read_nsopts(const char *confroot, struct vserver_conf *conf)
{
	int ret;
	uint_least64_t tmp;
	char *path = NULL;

	if (asprintf(&path, "%s/nsopts", confroot) == -1) {
		WARN("Memory allocation failed for path %s", confroot);
		return -1;
	}

	ret = read_capflags(path, PARAM_NS_OPTS, &tmp);
	if (ret)
		WARN_IFF_NOENT(ret, "nsopts");
	conf->nsopts = (int)tmp;

out:
	free(path);
	return ret;
}

#undef WARN_IFF_NOENT

int 
read_context(const char *confroot, struct vserver_conf *conf)
{
	int ret;

	ret = chdir(confroot);
	if (ret) {
		PERROR("chdir");
		return -1;
	}

	ret = do_read_context(conf);

	return ret;
}

static inline void
print_array(char **cmd) {
	int i = 0;
	while (cmd[i]) {
		printf(", %s", cmd[i]);
		++i;
	}
}

static int
do_exec(char *cmd, char **argv, char *envline, const struct passwd *pwd)
{
	char **margv, **menvp;
	const char *username, *home;
	int ret = -1;

	char *_argv[] = {
		NULL,
		NULL
	};

	if (pwd) {
		username = pwd->pw_name;
		home = pwd->pw_dir;
	} else {
		username = "root";
		home = "/root";
	}

	if (argv) {
		margv = argv;
		if (!margv[0]) {
			WARN("Enter with empty command ?");
			return -1;
		}
		if (margv[0][0] != '/') {
			WARN("Enter command \"%s\" must be given with "
			      "absolute path", margv[0]);
			return -1;
		}
	} else if (cmd) {
		_argv[0] = cmd;
		margv = _argv;
	} else {
		WARN("No command given");
		return -1;
	}

	if (envline) {
		menvp = setup_custom_envp(g_uid, username, home, envline);
		if (!menvp) {
			WARN("Could not setup custom environment");
			return -1;
		}
	} else {
		menvp = setup_envp(g_uid, username, home);
		if (!menvp) {
			WARN("Could not setup environment");
			return -1;
		}
	}

	(void)execve(margv[0], margv, menvp);
	PERROR("execve");
	ret = -1;

	/* Fall through from either */
	free_envp(menvp);

	return ret;
}

static int
close_all(int s)
{
	int ret, fd, nofiles;

	nofiles = getdtablesize();
	
	for (fd = STDERR_FILENO+1; fd < nofiles; ++fd) {
		if (fd == s) 
			continue;
		ret = close(fd);
		if (ret == -1 && errno != EBADF && errno != ENODEV) {
			PERROR("close");
			return -1;
		}
	}

	return 0;
}

static inline int 
netmask2preflen(const char *netmask)
{
	struct in_addr in;
	uint32_t hmask;
	unsigned int i;

	if (!inet_aton(netmask, &in))
		return -1;

	hmask = ntohl(in.s_addr);

	for (i = 0; i < 32; i++) {
		if ((hmask >> i) & 0x1)
			break;
	}

	return (32 - i);
}

static void __attribute__((noreturn))
namespace_callback_child(pid_t ns_id, struct vserver_conf *conf)
{
	char *argv[] = { NULL, NULL };
	/* layout of envp : 
	 * 	NS_PID
	 * 	JAIL_NAME
	 * 	JAIL_XID
	 * 	JAIL_NSOPTS
	 * 	JAIL_HOSTNAME
	 * 	JAIL_ADDR_1 ... JAIL_ADDR_<num_addrs>
	 * 	NULL
	 * => length is 6 + num_addrs
	 */
	char *envp[6 + conf->num_addrs];
	unsigned int i;

	memset(envp, 0, sizeof(envp));

	argv[0] = strdup(conf->ns_setup_cmd);
	if (!argv[0]) {
		WARN("Out of memory");
		goto fail;
	}

	if (asprintf(&envp[0], "NS_PID=%d", ns_id) == -1) {
		WARN("Failed to copy namespace pid");
		goto fail;
	}

	if (asprintf(&envp[1], "JAIL_NAME=%s", conf->name) == -1) {
		WARN("Failed to copy jail name");
		goto fail;
	}

	if (asprintf(&envp[2], "JAIL_XID=%lu", conf->xid) == -1) {
		WARN("Failed to copy jail xid");
		goto fail;
	}

	if (asprintf(&envp[3], "JAIL_NSOPTS=%s%s%s", 
			(conf->nsopts & CLIP_VSERVER_PIDNS) ? "P" : "",
			(conf->nsopts & CLIP_VSERVER_NETNS) ? "N" : "",
			(conf->nsopts & CLIP_VSERVER_USRNS) ? "U" : "") == -1) {
		WARN("Failed to copy namespace options");
		goto fail;
	}

	if (asprintf(&envp[4], "JAIL_HOSTNAME=%s", 
			(conf->hostname) ? conf->hostname : "") == -1) {
		WARN("Failed to copy jail xid");
		goto fail;
	}

	for (i = 0; i < conf->num_addrs; i++) {
		int pref;
		if (!conf->ipaddrs[i])
			continue;
		pref = netmask2preflen(conf->netmasks[i]);
		if (pref == -1)
			continue;
		if (asprintf(&envp[5 + i], "JAIL_ADDR_%u=%s/%d", 
				i, conf->ipaddrs[i], pref) == -1) {
			WARN("Failed to copy address %u", i);
			goto fail;
		}
	}

	exit(execve(argv[0], argv, envp));

fail:
	exit(EXIT_FAILURE);
}

static int
namespace_callback(pid_t ns_id, void *data)
{
	struct vserver_conf *conf = data;
	pid_t pid, ret;
	int status;
	
	if (!conf->ns_setup_cmd)
		return 0;

	DEBUG("Config %lu namespace : %d", conf->xid, ns_id);
	pid = fork();
	switch (pid) {
		case -1:
			PERROR("fork");
			return -1;
		case 0:
			namespace_callback_child(ns_id, conf);
			break;
		default:
			ret = waitpid(pid, &status, 0);
			if (ret == -1) {
				PERROR("wait");
				return -1;
			}

			if (WIFEXITED(status))
				return -1;

			if (WIFSIGNALED(status)) {
				return -1;
			}
			return 0;
	}
}

/*
 * Use g_uid and g_gid to set the UID, GID and groups.
 * Set *ret_passwd and return 0 if OK or -1 otherwise.
 */
static int
set_user_ids(struct passwd ** ret_passwd)
{
	int ret;
	struct passwd *passwd = NULL;

	passwd = getpwuid(g_uid);
	if (ret_passwd) {
		*ret_passwd = passwd;
	}
	if (!passwd) {
		WARN("Failure getting passwd");
	}
	if (!g_gid) {
		if (!passwd) {
			WARN("Group ID stay unchanged (root)");
		} else {
			g_gid = passwd->pw_gid;
		}
	}
	ret = setgid(g_gid);
	if (ret) {
		PERROR("setgid");
		return ret;
	}
	if (!passwd) {
		WARN("Resetting group list");
		ret = setgroups(0, NULL);
		if (ret) {
			PERROR("setgroups");
			return ret;
		}
	} else {
		ret = initgroups(passwd->pw_name, g_gid);
		if (ret) {
			PERROR("initgroups");
			return ret;
		}
	}
	if (g_uid) {
		ret = setuid(g_uid);
		if (ret) {
			PERROR("setuid");
			return ret;
		}
	}
	return 0;
}

int 
start_config(struct vserver_conf *conf, int setup_p)
{
	int ret = -1;
	int s = -1; /* shut up gcc */
	const char **ipaddrs = (void *)conf->ipaddrs;
	const char **netmasks = (void *)conf->netmasks;


	if (setup_p) {
		/* If we're setting up a PID NS context, we won't be
		 * able to detach after entering it (since we need to be
		 * the init of that context), so we force a detach before
		 * entering.
		 */
		if (conf->nsopts & CLIP_VSERVER_PIDNS) {
			if (!g_daemonize) {
				ret = clip_daemonize();
				if (ret) {
					WARN_ERRNO("Failed to daemonize self");
					return ret;
				}
			}
		}

		s = sock_prepare(conf->name);
		if (s < 0)
			return s;
	}

	if (g_vlogin) {
		ret = clip_vlogin();
		if (ret) {
			WARN_ERRNO("Failure setting up terminal proxy");
			goto out_close;
		}
	}

	ret = enter_cgroup(conf);
	if (ret) {
            WARN_ERRNO("failed to enter cgroup");
            goto out_close;
        }
        
	ret = clip_new_namespace_callback(conf->nsopts, 
					namespace_callback, conf);
	if (ret) {
		WARN_ERRNO("Failed to create namespaces");
		goto out_close;
	}

	ret = clip_new_net_context_multi(conf->xid, ipaddrs, 
					netmasks, conf->nflags);
	if (ret) {
		WARN_ERRNO("Failed to create net context");
		goto out_close;
	}

	if (conf->lback) {
		ret = clip_net_set_lback(conf->xid, conf->lback);
		if (ret) {
			WARN_ERRNO("Failed to set up loopback address");
			goto out_close;
		}
	}

	if (conf->bcast) {
		ret = clip_net_set_bcast(conf->xid, conf->bcast);
		if (ret) {
			WARN_ERRNO("Failed to set up broadcast address");
			goto out_close;
		}
	}

	if (conf->hostname) {
		ret = sethostname(conf->hostname, strlen (conf->hostname));
		if (ret)
			goto out_close;
	}
	ret = do_mounts(conf->mounts);
	if (ret) 
		goto out_close;
	ret = do_umounts(conf->umounts, 0);
	if (ret)
		goto out_close;

	ret = close_all((setup_p) ? s : 0);
	if (ret) {
		WARN("Failure to close open file descriptors");
		goto out_close;
	}
	
	ret = mount(conf->root, "/", "rootfs", MS_BIND|MS_REC, "");
	if (ret) {
		PERROR("mount");
		goto out_close;
	}
	ret = chdir(conf->root);
	if (ret) {
		PERROR("chdir");
		goto out_close;
	}
	ret = chroot(".");
	if (ret) {
		PERROR("chroot");
		goto out_close;
	}
	ret = clip_new_context_nsopts(conf->xid, conf->bcaps, 
				conf->ccaps, conf->cflags, conf->nsopts);
	if (ret) {
		WARN_ERRNO("Failed to create security context");
		goto out_close;
	}

	if (setup_p) {
		return sock_wait(s, (conf->nsopts & CLIP_VSERVER_PIDNS));
	} else {
		struct passwd *passwd = NULL;
		ret = set_user_ids(&passwd);
		if (ret) {
			return ret;
		}
		return do_exec(conf->cmd, NULL, g_envline, passwd);
	}

out_close:
	if (s != -1)
		close(s);
	return ret;
}

static int
enter_fixup(const struct vserver_conf *conf)
{
	int ret;
	if (!g_vlogin_post && !(conf->nsopts & CLIP_VSERVER_PIDNS))
		return 0;


	if (g_daemonize) {
		ret = clip_daemonize();
		if (ret)
			WARN("Failed to daemonize");
	} else {
		ret = clip_vlogin();
		if (ret)
			WARN("Failure setting up terminal proxy in context\n"
			      "Make sure /dev/pts is mounted and usable in "
			      "the jail.");
	}

	return ret;
}

int
enter_config(const struct vserver_conf *conf, char **argv)
{
	int ret;
	struct passwd *passwd = NULL;

	if (g_vlogin) {
		ret = clip_vlogin();
		if (ret) {
			WARN("Failure setting up terminal proxy");
			return ret;
		}
	}

	ret = enter_cgroup(conf);
	if (ret) {
            PERROR("failed to enter cgroup");
            return ret;
        }	
	
	ret = clip_enter_context(conf->xid);
	if (ret) {
		WARN("Failure entering context %lu", conf->xid);
		return ret;
	}

	if (enter_fixup(conf)) 
		return -1;

	if (g_chrootpath) {
		ret = chdir(g_chrootpath);
		if (ret) {
			PERROR("chdir");
			return ret;
		}
		ret = chroot(".");
		if (ret) {
			PERROR("chroot");
			return ret;
		}
	}	
	ret = set_user_ids(&passwd);
	if (ret) {
		return ret;
	}

	return do_exec(conf->cmd, argv, g_envline, passwd);
}

int
stop_config(const struct vserver_conf *conf)
{
	int ret = clip_enter_context(conf->xid);
	if (ret) {
		WARN("Failure entering context %lu", conf->xid);
		return ret;
	}
	/* If start command is done with UID & GID != 0, stop should be done with same UID & GID! */
	ret = set_user_ids(NULL);
	if (ret) {
		return ret;
	}

	ret = kill(-1, SIGTERM);
	if (ret) {
		WARN("Kill error : %s", strerror(errno));
		return ret;
	}
	usleep(1000000);
	ret = kill(-1, SIGKILL);

	return 0;
}
