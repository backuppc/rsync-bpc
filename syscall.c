/*
 * Syscall wrappers to ensure that nothing gets done in dry_run mode
 * and to handle system peculiarities.
 *
 * Copyright (C) 1998 Andrew Tridgell
 * Copyright (C) 2002 Martin Pool
 * Copyright (C) 2003-2009 Wayne Davison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, visit the http://fsf.org website.
 */

#include "rsync.h"

#if !defined MKNOD_CREATES_SOCKETS && defined HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_SYS_ATTR_H
#include <sys/attr.h>
#endif

extern int dry_run;
extern int am_root;
extern int read_only;
extern int list_only;
extern int preserve_perms;
extern int preserve_executability;

#define RETURN_ERROR_IF(x,e) \
	do { \
		if (x) { \
			errno = (e); \
			return -1; \
		} \
	} while (0)

#define RETURN_ERROR_IF_RO_OR_LO RETURN_ERROR_IF(read_only || list_only, EROFS)

int do_unlink(const char *fname)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return bpc_unlink(fname);
}

int do_symlink(const char *fname1, const char *fname2)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return bpc_symlink(fname1, fname2);
}

#ifdef HAVE_LINK
int do_link(const char *fname1, const char *fname2)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return bpc_link(fname1, fname2);
}
#endif

int do_lchown(const char *path, uid_t owner, gid_t group)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
#ifndef HAVE_LCHOWN
#define lchown chown
#endif
	return bpc_lchown(path, owner, group);
}

int do_mknod(const char *pathname, mode_t mode, dev_t dev)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

        return bpc_mknod(pathname, mode, dev);
}

int do_rmdir(const char *pathname)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return bpc_rmdir(pathname);
}

int do_open(const char *pathname, int flags, mode_t mode)
{
	if (flags != O_RDONLY) {
		RETURN_ERROR_IF(dry_run, 0);
		RETURN_ERROR_IF_RO_OR_LO;
	}

	return bpc_open(pathname, flags | O_BINARY, mode);
}

#ifdef HAVE_CHMOD
int do_chmod(const char *path, mode_t mode)
{
	int code;
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
#ifdef HAVE_LCHMOD
	code = bpc_lchmod(path, mode & CHMOD_BITS);
#else
	if (S_ISLNK(mode)) {
# if defined HAVE_SETATTRLIST
		struct attrlist attrList;
		uint32_t m = mode & CHMOD_BITS; /* manpage is wrong: not mode_t! */

		memset(&attrList, 0, sizeof attrList);
		attrList.bitmapcount = ATTR_BIT_MAP_COUNT;
		attrList.commonattr = ATTR_CMN_ACCESSMASK;
		code = setattrlist(path, &attrList, &m, sizeof m, FSOPT_NOFOLLOW);
# else
		code = 1;
# endif
	} else
		code = bpc_chmod(path, mode & CHMOD_BITS); /* DISCOURAGED FUNCTION */
#endif /* !HAVE_LCHMOD */
	if (code != 0 && (preserve_perms || preserve_executability))
		return code;
	return 0;
}
#endif

int do_rename(const char *fname1, const char *fname2)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return bpc_rename(fname1, fname2);
}

#ifdef HAVE_FTRUNCATE
int do_ftruncate(int fd, OFF_T size)
{
	int ret;

	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

	do {
		ret = bpc_ftruncate(fd, size);
	} while (ret < 0 && errno == EINTR);

	return ret;
}
#endif

void trim_trailing_slashes(char *name)
{
	int l;
	/* Some BSD systems cannot make a directory if the name
	 * contains a trailing slash.
	 * <http://www.opensource.apple.com/bugs/X/BSD%20Kernel/2734739.html> */

	/* Don't change empty string; and also we can't improve on
	 * "/" */

	l = strlen(name);
	while (l > 1) {
		if (name[--l] != '/')
			break;
		name[l] = '\0';
	}
}

int do_mkdir(char *fname, mode_t mode)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	trim_trailing_slashes(fname);
	return bpc_mkdir(fname, mode);
}

/* like mkstemp but forces permissions */
int do_mkstemp(char *template, mode_t perms, char *origFileName)
{
	RETURN_ERROR_IF(dry_run, 0);
	RETURN_ERROR_IF(read_only, EROFS);
	perms |= S_IWUSR;

#if defined HAVE_SECURE_MKSTEMP && defined HAVE_FCHMOD && (!defined HAVE_OPEN64 || defined HAVE_MKSTEMP64)
	{
		int fd = bpc_mkstemp(template, origFileName);
		if (fd == -1)
			return -1;
#if defined HAVE_SETMODE && O_BINARY
		setmode(fd, O_BINARY);
#endif
		return fd;
	}
#else
	if (!bpc_mktemp(template))
		return -1;
	return do_open(template, O_RDWR|O_EXCL|O_CREAT, perms);
#endif
}

int do_stat(const char *fname, STRUCT_STAT *st)
{
        return bpc_stat(fname, st);
}

int do_lstat(const char *fname, STRUCT_STAT *st)
{
        return bpc_lstat(fname, st);
}

int do_fstat(int fd, STRUCT_STAT *st)
{
        return bpc_fstat(fd, st);
}

OFF_T do_lseek(int fd, OFF_T offset, int whence)
{
	return bpc_lseek(fd, offset, whence);
}

#ifdef HAVE_LUTIMES
int do_lutimes(const char *fname, time_t modtime, uint32 mod_nsec)
{
	struct timeval t[2];

	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

	t[0].tv_sec = time(NULL);
	t[0].tv_usec = 0;
	t[1].tv_sec = modtime;
	t[1].tv_usec = mod_nsec / 1000;
	return bpc_lutimes(fname, t);
}
#endif

#ifdef HAVE_UTIMES
int do_utimes(const char *fname, time_t modtime, uint32 mod_nsec)
{
	struct timeval t[2];

	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;

	t[0].tv_sec = time(NULL);
	t[0].tv_usec = 0;
	t[1].tv_sec = modtime;
	t[1].tv_usec = mod_nsec / 1000;
	return bpc_utimes(fname, t);
}

#elif defined HAVE_UTIME
int do_utime(const char *fname, time_t modtime, UNUSED(uint32 mod_nsec))
{
	return bpc_utime(fname, modtime);
}

#else
#error Need utimes or utime function.
#endif
