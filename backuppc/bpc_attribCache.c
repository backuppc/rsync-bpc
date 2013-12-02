/*
 * Routines for caching multiple directories.
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

#define  BPC_ATTRIBCACHE_DIR_COUNT_MAX        (380)
#define  BPC_ATTRIBCACHE_DIR_HT_SIZE          (512)

void bpc_attribCache_init(bpc_attribCache_info *ac, char *hostName, int backupNum, char *shareNameUM, int compress)
{
    ac->backupNum     = backupNum;
    ac->compress      = compress;
    ac->cacheLruCnt   = 0;
    ac->bkupMergeList = NULL;
    ac->bkupMergeCnt  = 0;
    ac->currentDir[0] = '\0';
    strncpy(ac->hostName, hostName, BPC_MAXPATHLEN);
    ac->hostName[BPC_MAXPATHLEN - 1] = '\0';
    strncpy(ac->shareNameUM, shareNameUM, BPC_MAXPATHLEN);
    ac->shareNameUM[BPC_MAXPATHLEN - 1] = '\0';
    bpc_fileNameEltMangle(ac->shareName, BPC_MAXPATHLEN, ac->shareNameUM);
    ac->shareNameLen = strlen(ac->shareName);
    snprintf(ac->hostDir, BPC_MAXPATHLEN, "%s/pc/%s", BPC_TopDir, ac->hostName);
    snprintf(ac->backupTopDir, BPC_MAXPATHLEN, "%s/pc/%s/%d", BPC_TopDir, ac->hostName, ac->backupNum);
    bpc_path_create(ac->backupTopDir);

    bpc_hashtable_create(&ac->attrHT,  BPC_ATTRIBCACHE_DIR_HT_SIZE, sizeof(bpc_attribCache_dir));
    bpc_hashtable_create(&ac->inodeHT, BPC_ATTRIBCACHE_DIR_HT_SIZE, sizeof(bpc_attribCache_dir));
}

/*
 * Caller is responsible for calling malloc for bkupList.
 */
void bpc_attribCache_setMergeList(bpc_attribCache_info *ac, bpc_backup_info *bkupList, int bkupCnt)
{
    ac->bkupMergeList = bkupList;
    ac->bkupMergeCnt  = bkupCnt;
}

static void bpc_attribCache_destroyEntry(bpc_attribCache_dir *attr)
{
    bpc_attrib_dirDestroy(&attr->dir);
}

void bpc_attribCache_destroy(bpc_attribCache_info *ac)
{
    bpc_hashtable_iterate(&ac->attrHT,  (void*)bpc_attribCache_destroyEntry, NULL);
    bpc_hashtable_destroy(&ac->attrHT);
    bpc_hashtable_iterate(&ac->inodeHT, (void*)bpc_attribCache_destroyEntry, NULL);
    bpc_hashtable_destroy(&ac->inodeHT);
    if ( ac->bkupMergeList ) free(ac->bkupMergeList);
    ac->bkupMergeList = NULL;
    ac->bkupMergeCnt  = 0;
}

int bpc_attribCache_readOnly(bpc_attribCache_info *ac, int readOnly)
{
    if ( readOnly >= 0 ) ac->readOnly = readOnly;
    return ac->readOnly;
}

void bpc_attribCache_setCurrentDirectory(bpc_attribCache_info *ac, char *dir)
{
    char *p;
    snprintf(ac->currentDir, BPC_MAXPATHLEN, "%s", dir);
    p = ac->currentDir + strlen(ac->currentDir) - 1;
    while ( p >= ac->currentDir && p[0] == '/' ) *p-- = '\0';
}

/*
 * Given a backup path, split it into the directory, file name, and path to the directory (starting
 * with the share name, ie: relative to ac->backupTopDir).
 */
static void splitPath(bpc_attribCache_info *ac, char *dir, char *fileName, char *attribPath, char *path)
{
    char *dirOrig = dir;
    char fullPath[BPC_MAXPATHLEN];

    /*
     * if this is a relative path, prepend ac->currentDir (provided ac->currentDir is set)
     */
    if ( path[0] != '/' && ac->currentDir[0] ) {
        while ( path[0] == '.' && path[1] == '/' ) path += 2;
        while ( path[0] == '/' ) path++;
        snprintf(fullPath, BPC_MAXPATHLEN, "%s/%s", ac->currentDir, path);
        path = fullPath;
    }
    if ( !path[0] || (!path[1] && (path[0] == '.' || path[0] == '/')) ) {
        strcpy(fileName, ac->shareNameUM);
        strcpy(dir,  "/");
        strcpy(attribPath, "/attrib");
    } else {
        char *p;
        int dirLen = BPC_MAXPATHLEN - ac->shareNameLen;

        strcpy(dir, ac->shareName);
        dir += strlen(dir);
        if ( (p = strrchr(path, '/')) ) {
            if ( *path != '/' ) {
                *dir++ = '/'; dirLen--;
                *dir = '\0';
            }
            strcpy(fileName, p+1);
            *p = '\0';
            bpc_fileNameMangle(dir, dirLen, path);
            *p = '/';
        } else {
            strcpy(fileName, path);
        }
        snprintf(attribPath, BPC_MAXPATHLEN, "%s/attrib", dirOrig);
    }
    if ( BPC_LogLevel >= 9 ) bpc_logMsgf("splitPath: returning dir = '%s', fileName = '%s', attrib = '%s' from path = '%s'\n",
                            dirOrig, fileName, attribPath, path);
}

static void inodePath(UNUSED(bpc_attribCache_info *ac), char *indexStr, char *attribPath, ino_t inode)
{
    snprintf(attribPath, BPC_MAXPATHLEN, "inode/%02x/attrib%02x",
                        (unsigned int)(inode >> 17) & 0x7f, (unsigned int)(inode >> 10) & 0x7f);
    do {
        bpc_byte2hex(indexStr, inode & 0xff);
        indexStr += 2;
        inode >>= 8;
    } while ( inode );
    *indexStr = '\0';
}

static bpc_attribCache_dir *bpc_attribCache_loadPath(bpc_attribCache_info *ac, char *fileName, char *path)
{
    char dir[BPC_MAXPATHLEN], attribPath[BPC_MAXPATHLEN];
    bpc_attribCache_dir *attr;
    int attribPathLen, status;

    splitPath(ac, dir, fileName, attribPath, path);
    attribPathLen = strlen(attribPath);

    if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_attribCache_loadPath: path = %s -> dir = %s, fileName = %s, attribPath = %s\n", path, dir, fileName, attribPath);

    attr = bpc_hashtable_find(&ac->attrHT, (uchar*)attribPath, attribPathLen, 1);

    if ( !attr || attr->key.key != attribPath ) {
        /*
         * cache hit - return the existing attributes
         */
        if ( attr ) attr->lruCnt = ac->cacheLruCnt++;
        return attr;
    }

    if ( !(attr->key.key = malloc(attribPathLen + 1)) ) {
        bpc_logErrf("bpc_attribCache_loadPath: can't allocate %d bytes\n", attribPathLen + 1);
        return NULL;
    }
    strcpy(attr->key.key, attribPath);
    bpc_attrib_dirInit(&attr->dir, ac->compress);
    attr->dirty  = 0;
    attr->dirOk  = 0;
    attr->lruCnt = ac->cacheLruCnt++;

    if ( ac->bkupMergeCnt > 0 ) {
        int i;
        char topDir[BPC_MAXPATHLEN], fullAttribPath[BPC_MAXPATHLEN];

        /*
         * Merge multiple attrib files to create the "view" for this backup.
         * There are two cases: merging forward for v3, or merging in reverse
         * for v4+.  bkupMergeList is already in the order we need.
         */
        for ( i = 0 ; i < ac->bkupMergeCnt ; i++ ) {
            bpc_attrib_dir dir;
            ssize_t entrySize;
            char *entries, *fileName;
            int attribFileExists, attribDirExists = 1;
            STRUCT_STAT st;

            snprintf(topDir, sizeof(topDir), "%s/pc/%s/%d", BPC_TopDir, ac->hostName, ac->bkupMergeList[i].num);
            snprintf(fullAttribPath, sizeof(fullAttribPath), "%s/%s", topDir, attribPath);

            attribFileExists = !stat(fullAttribPath, &st) && S_ISREG(st.st_mode);

            if ( !attribFileExists ) {
                char *p;
                if ( (p = strrchr(fullAttribPath, '/')) ) {
                    *p = '\0';
                    attribDirExists = !stat(fullAttribPath, &st) && S_ISDIR(st.st_mode);
                }
            }
            if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_attribCache_loadPath: path = %s, file exists = %d, dir exists = %d\n", fullAttribPath, attribFileExists, attribDirExists);

            if ( ac->bkupMergeList[i].version < 4 && i == ac->bkupMergeCnt - 1 && !attribFileExists && !attribDirExists ) {
                /*
                 * For V3, if the last backup doesn't have a directory, then the merged view is empty
                 */
                bpc_attrib_dirDestroy(&attr->dir);
                bpc_attrib_dirInit(&attr->dir, ac->compress);
                break;
            }
            if ( !attribFileExists ) {
                /*
                 * nothing to update here - keep going
                 */
                continue;
            }
            bpc_attrib_dirInit(&dir, ac->bkupMergeList[i].compress);
            if ( (status = bpc_attrib_dirRead(&dir, topDir, attribPath, ac->bkupMergeList[i].num)) ) {
                bpc_logErrf("bpc_attribCache_loadPath: bpc_attrib_dirRead(%s/%s) returned %d\n", topDir, attribPath, status);
            }
            entrySize = bpc_attrib_getEntries(&dir, NULL, 0);
            if ( (entries = malloc(entrySize)) && bpc_attrib_getEntries(&dir, entries, entrySize) == entrySize ) {
                for ( fileName = entries ; fileName < entries + entrySize ; fileName += strlen(fileName) + 1 ) {
                    bpc_attrib_file *file = bpc_attrib_fileGet(&dir, fileName, 0);
                    if ( !file ) continue;
                    if ( file->type == BPC_FTYPE_DELETED ) {
                        bpc_attrib_fileDeleteName(&attr->dir, fileName);
                    } else {
                        bpc_attrib_file *fileDest;

                        if ( !(fileDest = bpc_attrib_fileGet(&attr->dir, fileName, 1)) ) return NULL;
                        if ( fileDest->key.key == fileName ) {
                            /*
                             * new entry - initialize
                             */
                            bpc_attrib_fileInit(fileDest, fileName, 0);
                        }
                        bpc_attrib_fileCopy(fileDest, file);
                        fileDest->backupNum = ac->bkupMergeList[i].num;
                    }
                }
            } else {
                bpc_logErrf("bpc_attribCache_loadPath(%s/%s): can't malloc %lu bytes for entries\n",
                                    topDir, attribPath, (unsigned long)entrySize);
                if ( entries ) free(entries);
                bpc_attrib_dirDestroy(&dir);
                return NULL;
            }
            free(entries);
            bpc_attrib_dirDestroy(&dir);
        }
    } else {
        /*
         * non-merge case - read the single attrib file
         */
        if ( (status = bpc_attrib_dirRead(&attr->dir, ac->backupTopDir, attribPath, ac->backupNum)) ) {
            bpc_logErrf("bpc_attribCache_loadPath: bpc_attrib_dirRead(%s, %s) returned %d\n", ac->backupTopDir, attribPath, status);
        }
    }
    if ( bpc_hashtable_entryCount(&ac->attrHT) > BPC_ATTRIBCACHE_DIR_COUNT_MAX ) {
        bpc_attribCache_flush(ac, 0, NULL);
    }
    return attr;
}

static bpc_attribCache_dir *bpc_attribCache_loadInode(bpc_attribCache_info *ac, char *indexStr, ino_t inode)
{
    char attribPath[BPC_MAXPATHLEN];
    bpc_attribCache_dir *attr;
    int attribPathLen, status;

    inodePath(ac, indexStr, attribPath, inode);
    attribPathLen = strlen(attribPath);

    attr = bpc_hashtable_find(&ac->inodeHT, (uchar*)attribPath, attribPathLen, 1);

    if ( !attr || attr->key.key != attribPath ) {
        if ( attr ) attr->lruCnt = ac->cacheLruCnt++;
        return attr;
    }

    /*
     * new entry - read the attrib file
     */
    if ( !(attr->key.key = malloc(attribPathLen + 1)) ) {
        bpc_logErrf("bpc_attribCache_loadInode: can't allocate %d bytes\n", attribPathLen + 1);
        return NULL;
    }
    strcpy(attr->key.key, attribPath);
    bpc_attrib_dirInit(&attr->dir, ac->compress);
    attr->dirty  = 0;
    attr->dirOk  = 1;
    attr->lruCnt = ac->cacheLruCnt++;
    if ( ac->bkupMergeCnt > 0 ) {
        int i;
        char topDir[BPC_MAXPATHLEN], fullAttribPath[BPC_MAXPATHLEN];

        /*
         * Merge multiple attrib files to create the "view" for this backup.
         * There is only one case here, v4, since v3 didn't have inodes. 
         */
        for ( i = 0 ; i < ac->bkupMergeCnt ; i++ ) {
            bpc_attrib_dir dir;
            ssize_t entrySize;
            char *entries, *fileName;
            int attribFileExists;
            STRUCT_STAT st;

            snprintf(topDir, sizeof(topDir), "%s/pc/%s/%d", BPC_TopDir, ac->hostName, ac->bkupMergeList[i].num);
            snprintf(fullAttribPath, sizeof(fullAttribPath), "%s/%s", topDir, attribPath);

            attribFileExists = !stat(fullAttribPath, &st) && S_ISREG(st.st_mode);

            if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_attribCache_loadInode: path = %s, file exists = %d\n", fullAttribPath, attribFileExists);

            if ( !attribFileExists ) {
                /*
                 * nothing to update here - keep going
                 */
                continue;
            }
            bpc_attrib_dirInit(&dir, ac->bkupMergeList[i].compress);
            if ( (status = bpc_attrib_dirRead(&dir, topDir, attribPath, ac->bkupMergeList[i].num)) ) {
                bpc_logErrf("bpc_attribCache_loadInode: bpc_attrib_dirRead(%s/%s) returned %d\n", topDir, attribPath, status);
            }
            entrySize = bpc_attrib_getEntries(&dir, NULL, 0);
            if ( (entries = malloc(entrySize)) && bpc_attrib_getEntries(&dir, entries, entrySize) == entrySize ) {
                for ( fileName = entries ; fileName < entries + entrySize ; fileName += strlen(fileName) + 1 ) {
                    bpc_attrib_file *file = bpc_attrib_fileGet(&dir, fileName, 0);
                    if ( !file ) continue;
                    if ( file->type == BPC_FTYPE_DELETED ) {
                        bpc_attrib_fileDeleteName(&attr->dir, fileName);
                    } else {
                        bpc_attrib_file *fileDest;

                        if ( !(fileDest = bpc_attrib_fileGet(&attr->dir, fileName, 1)) ) return NULL;
                        if ( fileDest->key.key == fileName ) {
                            /*
                             * new entry - initialize
                             */
                            bpc_attrib_fileInit(fileDest, fileName, 0);
                        }
                        bpc_attrib_fileCopy(fileDest, file);
                    }
                }
            } else {
                bpc_logErrf("bpc_attribCache_loadInode(%s/%s): can't malloc %lu bytes for entries\n",
                                    topDir, attribPath, (unsigned long)entrySize);
                if ( entries ) free(entries);
                bpc_attrib_dirDestroy(&dir);
                return NULL;
            }
            free(entries);
            bpc_attrib_dirDestroy(&dir);
        }
    } else {
        /*
         * non-merge case - read the single attrib file
         */
        if ( (status = bpc_attrib_dirRead(&attr->dir, ac->backupTopDir, attribPath, ac->backupNum)) ) {
            bpc_logErrf("bpc_attrib_dirRead: bpc_attrib_dirRead(%s/%s) returned %d\n", ac->backupTopDir, attribPath, status);
        }
    }
    if ( bpc_hashtable_entryCount(&ac->inodeHT) > BPC_ATTRIBCACHE_DIR_COUNT_MAX ) {
        bpc_attribCache_flush(ac, 0, NULL);
    }
    return attr;
}

bpc_attrib_file *bpc_attribCache_getFile(bpc_attribCache_info *ac, char *path, int allocate_if_missing, int dontReadInode)
{
    char fileName[BPC_MAXPATHLEN];
    bpc_attribCache_dir *attr;
    bpc_attrib_file *file;

    if ( !(attr = bpc_attribCache_loadPath(ac, fileName, path)) ) return NULL;
    attr->lruCnt = ac->cacheLruCnt++;
    if ( !(file = bpc_attrib_fileGet(&attr->dir, fileName, allocate_if_missing)) ) return NULL;

    if ( allocate_if_missing && file->key.key == fileName ) {
        /*
         * new entry - initialize
         */
        bpc_attrib_fileInit(file, fileName, 0);
        file->compress = ac->compress;
    }
    if ( dontReadInode || file->nlinks == 0 ) return file;

    return bpc_attribCache_getInode(ac, file->inode, allocate_if_missing);
}

int bpc_attribCache_setFile(bpc_attribCache_info *ac, char *path, bpc_attrib_file *file, int dontOverwriteInode)
{
    char fileName[BPC_MAXPATHLEN], indexStr[256];
    bpc_attribCache_dir *attr, *attrInode;
    bpc_attrib_file *fileDest;

    if ( !(attr = bpc_attribCache_loadPath(ac, fileName, path)) ) return -1;
    attr->lruCnt = ac->cacheLruCnt++;
    file->compress = ac->compress;

    if ( !(fileDest = bpc_attrib_fileGet(&attr->dir, fileName, 1)) ) return -1;

    if ( fileDest->key.key == fileName ) {
        /*
         * new entry - initialize
         */
        bpc_attrib_fileInit(fileDest, fileName, 0);
    }

    bpc_attrib_fileCopy(fileDest, file);
    attr->dirty = 1;
    if ( file->nlinks > 0 ) {
        bpc_attrib_file *inodeDest = bpc_attribCache_getInode(ac, file->inode, 0);
        if ( !dontOverwriteInode || !inodeDest ) {
            inodeDest = bpc_attribCache_getInode(ac, file->inode, 1);
            bpc_attrib_fileCopyOpt(inodeDest, file, 0);

            attrInode = bpc_attribCache_loadInode(ac, indexStr, file->inode);
            attrInode->dirty = 1;
            /*
             * remove the digest from the file attributes since the reference counting is reflected
             * by the inode (can't do this up above since fileDest might be the same as file).
             */
            fileDest->digest.len = 0;
            return 1;
        } else {
            /*
             * remove the digest from the file attributes since the reference counting is reflected
             * by the inode (can't do this up above since fileDest might be the same as file).
             */
            fileDest->digest.len = 0;
            return 0;
        }
    }
    return 1;
}

int bpc_attribCache_deleteFile(bpc_attribCache_info *ac, char *path)
{
    char fileName[BPC_MAXPATHLEN];
    bpc_attribCache_dir *attr;

    if ( !(attr = bpc_attribCache_loadPath(ac, fileName, path)) ) return -1;
    attr->lruCnt = ac->cacheLruCnt++;
    bpc_attrib_fileDeleteName(&attr->dir, fileName);
    attr->dirty = 1;
    return 0;
}

bpc_attrib_file *bpc_attribCache_getInode(bpc_attribCache_info *ac, ino_t inode, int allocate_if_missing)
{
    char indexStr[256];
    bpc_attribCache_dir *attr;
    bpc_attrib_file *file;

    if ( !(attr = bpc_attribCache_loadInode(ac, indexStr, inode)) ) return NULL;
    attr->lruCnt = ac->cacheLruCnt++;
    if ( !(file = bpc_attrib_fileGet(&attr->dir, indexStr, allocate_if_missing)) ) return NULL;

    if ( allocate_if_missing && file->key.key == indexStr ) {
        /*
         * new entry - initialize
         */
        bpc_attrib_fileInit(file, indexStr, 0);
        file->compress = ac->compress;
    }
    return file;
}

int bpc_attribCache_setInode(bpc_attribCache_info *ac, ino_t inode, bpc_attrib_file *inodeSrc)
{
    char indexStr[256];
    bpc_attribCache_dir *attr;
    bpc_attrib_file *inodeDest;

    if ( !(attr = bpc_attribCache_loadInode(ac, indexStr, inode)) ) return -1;
    attr->lruCnt = ac->cacheLruCnt++;
    if ( !(inodeDest = bpc_attrib_fileGet(&attr->dir, indexStr, 1)) ) return -1;

    if ( inodeDest->key.key == indexStr ) {
        /*
         * new entry - initialize
         */
        bpc_attrib_fileInit(inodeDest, indexStr, 0);
    }
    bpc_attrib_fileCopy(inodeDest, inodeSrc);
    attr->dirty = 1;
    return 0;
}

int bpc_attribCache_deleteInode(bpc_attribCache_info *ac, ino_t inode)
{
    char indexStr[256];
    bpc_attribCache_dir *attr;

    if ( !(attr = bpc_attribCache_loadInode(ac, indexStr, inode)) ) return -1;
    attr->lruCnt = ac->cacheLruCnt++;
    bpc_attrib_fileDeleteName(&attr->dir, indexStr);
    attr->dirty = 1;
    return 0;
}

int bpc_attribCache_getDirEntryCnt(bpc_attribCache_info *ac, char *path)
{
    bpc_attribCache_dir *attr;
    char fileName[BPC_MAXPATHLEN];
    size_t pathLen = strlen(path);

    /*
     * Append a fake file name so we actually open the directory's contents, not the directory entry one level up
     */
    if ( pathLen >= BPC_MAXPATHLEN - 3 ) return -1;
    strcpy(path + pathLen, "/x");
    attr = bpc_attribCache_loadPath(ac, fileName, path);
    path[pathLen] = '\0';
    if ( !attr ) return -1;
    return bpc_hashtable_entryCount(&attr->dir.filesHT);
}

typedef struct {
    char *entries;
    ssize_t entryIdx;
    ssize_t entrySize;
} dirEntry_info;

static void bpc_attribCache_getDirEntry(bpc_attrib_file *file, dirEntry_info *info)
{
    ssize_t len = strlen(file->name) + 1;

    if ( info->entryIdx < 0 ) return;
    if ( info->entries ) {
        if ( info->entryIdx + len + (ssize_t)sizeof(ino_t) > info->entrySize ) {
            info->entryIdx = -1;
            return;
        }
        memcpy(info->entries + info->entryIdx, file->name, len);
        info->entryIdx += len;
        memcpy(info->entries + info->entryIdx, &file->inode, sizeof(ino_t));
        info->entryIdx += sizeof(ino_t);
    } else {
        info->entryIdx += len + sizeof(ino_t);
    }
}

ssize_t bpc_attribCache_getDirEntries(bpc_attribCache_info *ac, char *path, char *entries, ssize_t entrySize)
{
    bpc_attribCache_dir *attr;
    char fileName[BPC_MAXPATHLEN];
    dirEntry_info info;
    size_t pathLen = strlen(path);
    ino_t inode = 0;

    /*
     * Append a fake file name so we actually open the directory's contents, not the directory entry one level up
     */
    if ( pathLen >= BPC_MAXPATHLEN - 3 ) return -1;
    if ( pathLen == 1 && path[0] == '.' ) {
        strcpy(path, "/x");
        attr = bpc_attribCache_loadPath(ac, fileName, path);
        strcpy(path, ".");
    } else {
        strcpy(path + pathLen, "/x");
        attr = bpc_attribCache_loadPath(ac, fileName, path);
        path[pathLen] = '\0';
    }
    if ( !attr ) return -1;
    attr->lruCnt = ac->cacheLruCnt++;

    info.entries   = entries;
    info.entryIdx  = 0;
    info.entrySize = entrySize;

    if ( entries && entrySize >= (ssize_t)(5 + 2 * sizeof(ino_t)) ) {
        strcpy(info.entries + info.entryIdx, ".");
        info.entryIdx += 2;
        /* dummy inode number */
        memcpy(info.entries + info.entryIdx, &inode, sizeof(inode));
        info.entryIdx += sizeof(inode);

        strcpy(info.entries + info.entryIdx, "..");
        info.entryIdx += 3;
        /* dummy inode number */
        memcpy(info.entries + info.entryIdx, &inode, sizeof(inode));
        info.entryIdx += sizeof(inode);

    } else {
        info.entryIdx += 5 + 2 * sizeof(ino_t);
    }

    bpc_hashtable_iterate(&attr->dir.filesHT, (void*)bpc_attribCache_getDirEntry, &info);
    return info.entryIdx;
}

typedef struct {
    char *path;
    int pathLen;
    int all;
    bpc_attribCache_info *ac;
    int entryCnt;
    int entryIdx;
    bpc_attribCache_dir **entries;
    bpc_hashtable *ht;
    int errorCnt;
} flush_info;

static void bpc_attribCache_dirWrite(bpc_attribCache_dir *attr, flush_info *info)
{
    int status;

    if ( !info->ac->readOnly && !info->all && info->path ) {
        if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_attribCache_dirWrite: comparing %s vs key %s\n", info->path, attr->key.key);
        if ( strncmp(info->path, attr->key.key, info->pathLen)
                || (((char*)attr->key.key)[info->pathLen] != '/' && ((char*)attr->key.key)[info->pathLen] != '\0') ) {
            if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_attribCache_dirWrite: skipping %s (doesn't match %s)\n", (char*)attr->key.key, info->path);
            return;
        }
    }
    if ( !info->ac->readOnly && attr->dirty ) {
        bpc_digest *oldDigest = bpc_attrib_dirDigestGet(&attr->dir);
        if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_attribCache_dirWrite: writing %s/%s with %d entries\n",
                                            info->ac->backupTopDir, (char*)attr->key.key, bpc_hashtable_entryCount(&attr->dir.filesHT));
        if ( (status = bpc_attrib_dirWrite(&attr->dir, info->ac->backupTopDir, attr->key.key, oldDigest)) ) {
            bpc_logErrf("bpc_attribCache_dirWrite: failed to write attributes for dir %s\n", (char*)attr->key.key);
            info->errorCnt++;
        }
    }

    /*
     * Now deallocate memory
     */
    bpc_attrib_dirDestroy(&attr->dir);
    if ( attr->key.key ) free(attr->key.key);
    bpc_hashtable_nodeDelete(info->ht, attr);
}

static void bpc_attribCache_flush_lruListFill(bpc_attribCache_dir *attr, flush_info *info)
{
    if ( info->entryIdx >= info->entryCnt ) return;
    info->entries[info->entryIdx++] = attr;
}

static int bpc_attribCache_flush_lruCompare(bpc_attribCache_dir **d1, bpc_attribCache_dir **d2)
{
    return (*d1)->lruCnt - (*d2)->lruCnt;
}

/*
 * Build a list of all entries in the hash table, sorted by LRU count from lowest to highest
 */
static void bpc_attribCache_flush_lruList(flush_info *info)
{
    int i;

    /*
     * allocate list of all entries
     */
    info->entryCnt = bpc_hashtable_entryCount(info->ht);
    info->entryIdx = 0;
    info->entries = NULL;
    if ( info->entryCnt == 0 ) return;
    if ( !(info->entries = malloc(info->entryCnt * sizeof(*info->entries))) ) {
        bpc_logErrf("bpc_attribCache_flush_lruList: can't allocated %lu bytes\n", (unsigned long)info->entryCnt * sizeof(*info->entries));
        return;
    }
    bpc_hashtable_iterate(info->ht, (void*)bpc_attribCache_flush_lruListFill, info);

    /*
     * sort by lruCnt, from lowest to highest
     */
    qsort(info->entries, info->entryCnt, sizeof(*info->entries), (void*)bpc_attribCache_flush_lruCompare);

    /*
     * Now flush the oldest half of the entries
     */
    for ( i = 0 ; i < info->entryCnt / 2 ; i++ ) {
        bpc_attribCache_dirWrite(info->entries[i], info);
    }

    if ( info->entries ) free(info->entries);
}

/*
 * Flush some or all of the cache.  If all, then flush everything.  If path is not NULL
 * then just those entries that start with that path are flushed.
 */
void bpc_attribCache_flush(bpc_attribCache_info *ac, int all, char *path)
{
    flush_info info;
    char attribPath[BPC_MAXPATHLEN];

    info.all      = all;
    info.ac       = ac;
    if ( path ) {
        char pathDeep[BPC_MAXPATHLEN];
        char fileName[BPC_MAXPATHLEN], dir[BPC_MAXPATHLEN];

        snprintf(pathDeep, BPC_MAXPATHLEN, "%s/foo", path);
        splitPath(ac, dir, fileName, attribPath, pathDeep);
        info.path    = attribPath;
        info.pathLen = strlen(info.path);
    } else {
        info.path    = NULL;
        info.pathLen = 0;
    }
    info.entryCnt = 0;
    info.entryIdx = 0;
    info.entries  = NULL;
    info.errorCnt = 0;

    if ( !all && !path ) {
        /*
         * flush the oldest half of the entries based on the lruCnt
         */
        info.ht = &ac->attrHT;
        bpc_attribCache_flush_lruList(&info);
        info.ht = &ac->inodeHT;
        bpc_attribCache_flush_lruList(&info);
    } else {
        info.ht = &ac->attrHT;
        bpc_hashtable_iterate(&ac->attrHT, (void*)bpc_attribCache_dirWrite, &info);
        info.ht = &ac->inodeHT;
        bpc_hashtable_iterate(&ac->inodeHT, (void*)bpc_attribCache_dirWrite, &info);
    }
    if ( info.errorCnt ) {
        /*
         * Any errors likely mean the deltas are probably out of sync with the
         * file system, so request an fsck.
         */
        bpc_poolRefRequestFsck(ac->hostDir, 1);
    }
}

/*
 * Returns the full mangled path, given a file path.
 */
void bpc_attribCache_getFullMangledPath(bpc_attribCache_info *ac, char *path, char *dirName, int backupNum)
{
    char *p;
    int len;

    do {
        p = dirName;
        while ( dirName[0] == '.' && dirName[1] == '/' ) dirName += 2;
        while ( dirName[0] == '/' ) dirName++;
    } while ( p != dirName );

    if ( backupNum < 0 || ac->bkupMergeCnt <= 0 ) {
        backupNum = ac->backupNum;
    }

    len = snprintf(path, BPC_MAXPATHLEN, "%s/pc/%s/%d/%s", BPC_TopDir, ac->hostName, backupNum, ac->shareName);
    if ( (dirName[0] == '/' && dirName[1] == '\0') || dirName[0] == '\0' || len >= BPC_MAXPATHLEN - 1 ) {
        return;
    }
    path[len++] = '/';
    bpc_fileNameMangle(path + len, BPC_MAXPATHLEN - len, dirName);
}
