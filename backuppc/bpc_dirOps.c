/*
 * Directory and file system operations
 *
 * Copyright (C) 2013 Craig Barratt.
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

#include "backuppc.h"

/*
 * Create all the directories in the given path.  Path must be non-const.  Trailing '/' characters are removed.
 */
int bpc_path_create(char *path)
{
    char *p = path;
    STRUCT_STAT st;
    int levels = 0;

    if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_path_create(%s)\n", path);
    /*
     * check if it exists already
     */
    if ( !stat(path, &st) && S_ISDIR(st.st_mode) ) return 0;

    /*
     * We walk up until we find the deepest level directory that exists.
     * First remove trailing slashes.
     */
    p = path + strlen(path);
    while ( p > path && p[-1] == '/' ) p--;
    if ( *p == '/' ) *p = '\0';
    while ( p > path ) {
        while ( p > path && p[-1] != '/' ) p--;
        while ( p > path && p[-1] == '/' ) p--;
        if ( *p == '/' ) {
            *p = '\0';
            levels++;
            if ( !stat(path, &st) && S_ISDIR(st.st_mode) ) break;
        }
    }
    if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_path_create: found that %s exists (%d levels up)\n", path, levels);

    /*
     * We have removed levels '/' characters from path.  Replace each one and create the directory.
     */
    while ( levels-- > 0 ) {
        p = path + strlen(path);
        *p = '/';
        if ( mkdir(path, ACCESSPERMS) < 0 && errno != EEXIST) {
            bpc_logErrf("bpc_path_create: can't create %s (errno %d)\n", path, errno);
            return -1;
        }
        if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_path_create: created %s\n", path);
    }
    return 0;
}

/*
 * Remove all the files below path (if a directory) and path itself.  Deduct reference counts
 * for every attrib file removed.
 *
 * Note that inodes are *not* updated, even in cases where nlinks > 0.
 */
int bpc_path_remove(char *path, int compress)
{
    char filePath[BPC_MAXPATHLEN];
    STRUCT_STAT st;
    DIR *dir;
    struct dirent *dp;
    int errorCnt = 0;
    size_t dirListSize = 0, dirListLen = 0;
    char *dirList = NULL, *dirListP;

    if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_path_remove(%s)\n", path);
    if ( !(dir = opendir(path)) ) {
        unlink(path);
        return errorCnt;
    }
    while ( (dp = readdir(dir)) ) {
        if ( !strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..") ) continue;
        snprintf(filePath, sizeof(filePath), "%s/%s", path, dp->d_name);
        if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_path_remove: removing %s\n", filePath);
        if ( stat(filePath, &st) ) {
            /*
             * hmmm.  stat failed - just try to remove it
             */
            unlink(filePath);
            continue;
        }
        if ( S_ISDIR(st.st_mode) ) {
            /*
             * To avoid recursing with dir still open (consuming an open fd), remember all the dirs
             * and recurse after we close dir.
             */
            if ( !dirList ) {
                dirListSize = 4096;
                if ( !(dirList = malloc(dirListSize)) ) {
                    bpc_logErrf("bpc_path_refCountAll: can't allocate %u bytes\n", (unsigned)dirListSize);
                    return ++errorCnt;
                }
            }
            if ( dirListLen + strlen(dp->d_name) + 1 >= dirListSize ) {
                dirListSize = dirListSize * 2 + strlen(dp->d_name);
                if ( !(dirList = realloc(dirList, dirListSize)) ) {
                    bpc_logErrf("bpc_path_refCountAll: can't reallocate %u bytes\n", (unsigned)dirListSize);
                    return ++errorCnt;
                }
            }
            strcpy(dirList + dirListLen, dp->d_name);
            dirListLen += strlen(dp->d_name) + 1;
        } else {
            /*
             * if this is an attrib file, we need to read it and deduct the reference counts.
             */
            if ( !strncmp(dp->d_name, "attrib", 6) ) {
                bpc_attrib_dir dir;

                bpc_attrib_dirInit(&dir, compress);
                if ( bpc_attrib_dirRead(&dir, NULL, filePath, 0) ) {
                    bpc_logErrf("bpc_path_remove: can't read attrib file %s\n", filePath);
                    errorCnt++;
                }
                if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_path_remove: adjusting ref counts from attrib file %s\n", filePath);
                if ( !unlink(filePath) ) {
                    /*
                     * Only reduce the ref counts if we succeeded in removing the attrib file
                     */
                    bpc_attrib_dirRefCount(&dir, -1);
                }
                bpc_attrib_dirDestroy(&dir);
            } else {
                if ( unlink(filePath) ) errorCnt++;
            }
        }
    }
    closedir(dir);
    /*
     * Now visit the subdirs we have saved above.
     */
    if ( dirList ) {
        for ( dirListP = dirList ; dirListP < dirList + dirListLen ; dirListP += strlen(dirListP) + 1 ) {
            snprintf(filePath, sizeof(filePath), "%s/%s", path, dirListP);
            errorCnt += bpc_path_remove(filePath, compress);
        }
        free(dirList);
    }
    if ( rmdir(path) ) errorCnt++;
    return errorCnt;
}

/*
 * Reference count all the files below the directory path, based on the attrib
 * files in and below path.
 */
int bpc_path_refCountAll(char *path, int compress)
{
    char filePath[BPC_MAXPATHLEN];
    STRUCT_STAT st;
    DIR *dir;
    struct dirent *dp;
    int errorCnt = 0;
    size_t dirListSize = 0, dirListLen = 0;
    char *dirList = NULL, *dirListP;

    if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_path_refCountAll(%s)\n", path);
    if ( !(dir = opendir(path)) ) {
        return errorCnt;
    }
    while ( (dp = readdir(dir)) ) {
        if ( !strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..") ) continue;
        snprintf(filePath, sizeof(filePath), "%s/%s", path, dp->d_name);
        if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_path_refCountAll: got %s\n", filePath);
        if ( stat(filePath, &st) ) continue;
        if ( S_ISDIR(st.st_mode) ) {
            /*
             * To avoid recursing with dir still open (consuming an open fd), remember all the dirs
             * and recurse after we close dir.
             */
            if ( !dirList ) {
                dirListSize = 4096;
                if ( !(dirList = malloc(dirListSize)) ) {
                    bpc_logErrf("bpc_path_refCountAll: can't allocate %u bytes\n", (unsigned)dirListSize);
                    return ++errorCnt;
                }
            }
            if ( dirListLen + strlen(dp->d_name) + 1 >= dirListSize ) {
                dirListSize = dirListSize * 2 + strlen(dp->d_name);
                if ( !(dirList = realloc(dirList, dirListSize)) ) {
                    bpc_logErrf("bpc_path_refCountAll: can't reallocate %u bytes\n", (unsigned)dirListSize);
                    return ++errorCnt;
                }
            }
            strcpy(dirList + dirListLen, dp->d_name);
            dirListLen += strlen(dp->d_name) + 1;
        } else {
            /*
             * if this is an attrib file, we need to read it and deduct the reference counts.
             */
            if ( !strncmp(dp->d_name, "attrib", 6) ) {
                bpc_attrib_dir dir;

                bpc_attrib_dirInit(&dir, compress);
                if ( bpc_attrib_dirRead(&dir, NULL, filePath, 0) ) {
                    bpc_logErrf("bpc_path_refCountAll: can't read attrib file %s\n", filePath);
                    errorCnt++;
                } else {
                    if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_path_refCountAll: adjusting ref counts from attrib file %s\n", filePath);
                    bpc_attrib_dirRefCount(&dir, 1);
                    bpc_attrib_dirDestroy(&dir);
                }
            }
        }
    }
    closedir(dir);
    /*
     * Now visit the subdirs we have saved above.
     */
    if ( dirList ) {
        for ( dirListP = dirList ; dirListP < dirList + dirListLen ; dirListP += strlen(dirListP) + 1 ) {
            snprintf(filePath, sizeof(filePath), "%s/%s", path, dirListP);
            errorCnt += bpc_path_refCountAll(filePath, compress);
        }
        free(dirList);
    }
    return errorCnt;
}

/*
 * Add an exclusive lock to the byte range in the given file.
 * Blocks until the lock becomes available.
 */
int bpc_lockRangeFd(int fd, OFF_T offset, OFF_T len, int block)
{
    struct flock lock;

    lock.l_type   = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start  = offset;
    lock.l_len    = len;
    lock.l_pid    = 0;

    return fcntl(fd, block ? F_SETLKW : F_SETLK, &lock);
}

int bpc_unlockRangeFd(int fd, OFF_T offset, OFF_T len)
{
    struct flock lock;

    lock.l_type   = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start  = offset;
    lock.l_len    = len;
    lock.l_pid    = 0;

    return fcntl(fd, F_SETLK, &lock);
}

int bpc_lockRangeFile(char *lockFile, OFF_T offset, OFF_T len, int block)
{
    int fd;

    if ( (fd = open(lockFile, O_CREAT | O_RDWR, 0660)) < 0 ) {
        bpc_logErrf("bpc_lockRangeFile: can't open/create lock file %s\n", lockFile);
        return fd;
    }
    if ( bpc_lockRangeFd(fd, offset, len, block) ) {
        close(fd);
        if ( block ) {
            bpc_logErrf("bpc_lockRangeFile: lock(%s) failed (errno = %d)\n", lockFile, errno);
        }
        return -1;
    }
    return fd;
}

void bpc_unlockRangeFile(int lockFd)
{
    if ( lockFd >= 0 ) close(lockFd);
}
