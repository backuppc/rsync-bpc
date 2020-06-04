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
    ac->deltaInfo     = NULL;

    ac->shareName     = bpc_strBuf_new();
    ac->shareNameUM   = bpc_strBuf_new();
    ac->hostName      = bpc_strBuf_new();
    ac->backupTopDir  = bpc_strBuf_new();
    ac->currentDir    = bpc_strBuf_new();

    bpc_strBuf_strcpy(ac->hostName,       0, hostName);
    bpc_strBuf_strcpy(ac->shareNameUM,    0, shareNameUM);
    bpc_fileNameEltMangle(ac->shareName,  ac->shareNameUM->s);
    bpc_strBuf_snprintf(ac->backupTopDir, 0, "%s/pc/%s/%d", BPC_TopDir.s, ac->hostName->s, ac->backupNum);
    bpc_strBuf_strcpy(ac->currentDir,     0, "");

    bpc_path_create(ac->backupTopDir->s);

    bpc_hashtable_create(&ac->attrHT,  BPC_ATTRIBCACHE_DIR_HT_SIZE, sizeof(bpc_attribCache_dir));
    bpc_hashtable_create(&ac->inodeHT, BPC_ATTRIBCACHE_DIR_HT_SIZE, sizeof(bpc_attribCache_dir));
}

void bpc_attribCache_setDeltaInfo(bpc_attribCache_info *ac, bpc_deltaCount_info *deltaInfo)
{
    ac->deltaInfo = deltaInfo;
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
    bpc_strBuf_free(ac->shareName);
    bpc_strBuf_free(ac->shareNameUM);
    bpc_strBuf_free(ac->hostName);
    bpc_strBuf_free(ac->backupTopDir);
    bpc_strBuf_free(ac->currentDir);
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
    bpc_strBuf_strcpy(ac->currentDir, 0, dir);
    p = ac->currentDir->s + strlen(ac->currentDir->s) - 1;
    while ( p >= ac->currentDir->s && p[0] == '/' ) *p-- = '\0';
}

/*
 * Given a backup path, split it into the directory, file name, and path to the directory (starting
 * with the share name, ie: relative to ac->backupTopDir->s).
 *
 * splitPath will strip initial "./" and trailing "/." or "/" before splitting the path, but isn't
 * capable of handling paths with "/." in the middle, or ".." anywhere.
 */
static void splitPath(bpc_attribCache_info *ac, bpc_strBuf *dir, bpc_strBuf *fileName, bpc_strBuf *attribPath, char *path)
{
    bpc_strBuf *fullPath = bpc_strBuf_new();
    size_t pathLen;

    /*
     * remove initial "./"
     */
    while ( path[0] == '.' && path[1] == '/' ) {
        path += 2;
        while ( path[0] == '/' ) path++;
    }

    /*
     * if this is a relative path, prepend ac->currentDir->s (provided ac->currentDir->s is set)
     */
    if ( path[0] != '/' && ac->currentDir->s[0] ) {
        bpc_strBuf_snprintf(fullPath, 0, "%s/%s", ac->currentDir->s, path);
        path = fullPath->s;
    }

    /*
     * strip trailing "/." or "/" 
     */
    pathLen = strlen(path);
    while ( (pathLen > 1 && path[pathLen - 2] == '/' && path[pathLen - 1] == '.')
         || (pathLen > 0 && path[pathLen - 1] == '/') ) {
        if ( path != fullPath->s ) {
            bpc_strBuf_strcpy(fullPath, 0, path);
            path = fullPath->s;
        }
        if ( path[pathLen - 1] == '/' ) {
            pathLen -= 1;
        } else {
            pathLen -= 2;
        }
        path[pathLen] = '\0';
        if ( BPC_LogLevel >= 9 ) bpc_logMsgf("splitPath: trimming path = '%s'\n", path);
    }
    if ( !path[0] || (!path[1] && (path[0] == '.' || path[0] == '/')) ) {
        bpc_strBuf_strcpy(fileName, 0, ac->shareNameUM->s);
        bpc_strBuf_strcpy(dir, 0, "/");
        bpc_strBuf_strcpy(attribPath, 0, "/attrib");
    } else {
        char *p;
        int i;

        bpc_strBuf_strcpy(dir, 0, ac->shareName->s);
        i = strlen(dir->s);
        if ( (p = strrchr(path, '/')) ) {
            if ( *path != '/' ) {
                bpc_strBuf_strcat(dir, i++, "/");
            }
            bpc_strBuf_strcpy(fileName, 0, p+1);
            *p = '\0';
            bpc_fileNameMangle(dir, path, i);
            *p = '/';
        } else {
            bpc_strBuf_strcpy(fileName, 0, path);
        }
        bpc_strBuf_snprintf(attribPath, 0, "%s/attrib", dir->s);
    }
    if ( BPC_LogLevel >= 9 ) bpc_logMsgf("splitPath: returning dir = '%s', fileName = '%s', attrib = '%s' from path = '%s'\n",
                            dir->s, fileName->s, attribPath->s, path);
    bpc_strBuf_free(fullPath);
}

static void inodePath(UNUSED(bpc_attribCache_info *ac), char *indexStr, bpc_strBuf *attribPath, bpc_strBuf *attribFile, ino_t inode)
{
    bpc_strBuf_snprintf(attribPath, 0, "inode/%02x", (unsigned int)(inode >> 17) & 0x7f);
    bpc_strBuf_snprintf(attribFile, 0, "attrib%02x", (unsigned int)(inode >> 10) & 0x7f);
    do {
        bpc_byte2hex(indexStr, inode & 0xff);
        indexStr += 2;
        inode >>= 8;
    } while ( inode );
    *indexStr = '\0';
}

static void bpc_attribCache_removeDeletedEntries(bpc_attrib_file *file, void *arg)
{
    bpc_attribCache_dir *attr = (bpc_attribCache_dir*)arg;
    if ( file->type != BPC_FTYPE_DELETED ) return;
    attr->dirty = 1;
    bpc_attrib_fileDestroy(file);
    bpc_hashtable_nodeDelete(&attr->dir.filesHT, file);
}

static bpc_attribCache_dir *bpc_attribCache_loadPath(bpc_attribCache_info *ac, bpc_strBuf *fileName, char *path)
{
    bpc_strBuf *dirStr = bpc_strBuf_new(), *attribPath = bpc_strBuf_new();
    bpc_attribCache_dir *attr;
    int attribPathLen, status;

    splitPath(ac, dirStr, fileName, attribPath, path);
    attribPathLen = strlen(attribPath->s);

    if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_attribCache_loadPath: path = %s -> dir = %s, fileName = %s, attribPath = %s\n", path, dirStr->s, fileName, attribPath->s);
    bpc_strBuf_free(dirStr);

    attr = bpc_hashtable_find(&ac->attrHT, (uchar*)attribPath->s, attribPathLen, 1);

    if ( !attr || attr->key.key != attribPath->s ) {
        /*
         * cache hit - return the existing attributes
         */
        if ( attr ) attr->lruCnt = ac->cacheLruCnt++;
        bpc_strBuf_free(attribPath);
        return attr;
    }

    if ( !(attr->key.key = malloc(attribPathLen + 1)) ) {
        bpc_logErrf("bpc_attribCache_loadPath: can't allocate %d bytes\n", attribPathLen + 1);
        bpc_strBuf_free(attribPath);
        return NULL;
    }
    strcpy(attr->key.key, attribPath->s);
    bpc_attrib_dirInit(&attr->dir, ac->compress);
    attr->dirty  = 0;
    attr->dirOk  = 0;
    attr->lruCnt = ac->cacheLruCnt++;

    if ( ac->bkupMergeCnt > 0 ) {
        int i;
        bpc_strBuf *topDir = bpc_strBuf_new(), *fullAttribPath = bpc_strBuf_new();

        /*
         * Merge multiple attrib files to create the "view" for this backup.
         * There are two cases: merging forward for v3, or merging in reverse
         * for v4+.  bkupMergeList is already in the order we need.
         */
        for ( i = 0 ; i < ac->bkupMergeCnt ; i++ ) {
            bpc_attrib_dir dir;
            ssize_t entrySize;
            char *entries, *fileName;

            bpc_strBuf_snprintf(topDir, 0, "%s/pc/%s/%d", BPC_TopDir.s, ac->hostName->s, ac->bkupMergeList[i].num);
            bpc_strBuf_snprintf(fullAttribPath, 0, "%s/%s", topDir->s, attribPath->s);

            bpc_attrib_dirInit(&dir, ac->bkupMergeList[i].compress);
            if ( (status = bpc_attrib_dirRead(&dir, topDir->s, attribPath->s, ac->bkupMergeList[i].num)) ) {
                if ( ac->bkupMergeList[i].version < 4 ) {
                    char *p;
                    int attribDirExists = 1;
                    STRUCT_STAT st;

                    if ( (p = strrchr(fullAttribPath->s, '/')) ) {
                        *p = '\0';
                        attribDirExists = !stat(fullAttribPath->s, &st) && S_ISDIR(st.st_mode);
                        *p = '/';
                    }
                    if ( i == ac->bkupMergeCnt - 1 && !attribDirExists ) {
                        /*
                         * For V3, if the last backup doesn't have a directory, then the merged view is empty
                         */
                        bpc_attrib_dirDestroy(&dir);
                        bpc_attrib_dirDestroy(&attr->dir);
                        bpc_attrib_dirInit(&attr->dir, ac->compress);
                        break;
                    }
                    if ( !attribDirExists ) {
                        /*
                         * nothing to update here - keep going
                         */
                        bpc_attrib_dirDestroy(&dir);
                        continue;
                    }
                }
                bpc_logErrf("bpc_attribCache_loadPath: bpc_attrib_dirRead(%s/%s) returned %d\n", topDir->s, attribPath->s, status);
            }
            entrySize = bpc_attrib_getEntries(&dir, NULL, 0);
            if ( (entries = malloc(entrySize + 1)) && bpc_attrib_getEntries(&dir, entries, entrySize) == entrySize ) {
                for ( fileName = entries ; fileName < entries + entrySize ; fileName += strlen(fileName) + 1 ) {
                    bpc_attrib_file *file = bpc_attrib_fileGet(&dir, fileName, 0);
                    if ( !file ) continue;
                    if ( file->type == BPC_FTYPE_DELETED ) {
                        bpc_attrib_fileDeleteName(&attr->dir, fileName);
                    } else {
                        bpc_attrib_file *fileDest;

                        if ( !(fileDest = bpc_attrib_fileGet(&attr->dir, fileName, 1)) ) {
                            bpc_strBuf_free(attribPath);
                            bpc_strBuf_free(topDir);
                            bpc_strBuf_free(fullAttribPath);
                            return NULL;
                        }
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
                                    topDir->s, attribPath->s, (unsigned long)entrySize);
                if ( entries ) free(entries);
                bpc_attrib_dirDestroy(&dir);
                bpc_strBuf_free(attribPath);
                bpc_strBuf_free(topDir);
                bpc_strBuf_free(fullAttribPath);
                return NULL;
            }
            free(entries);
            bpc_attrib_dirDestroy(&dir);
        }
        bpc_strBuf_free(topDir);
        bpc_strBuf_free(fullAttribPath);
    } else {
        /*
         * non-merge case - read the single attrib file
         */
        if ( (status = bpc_attrib_dirRead(&attr->dir, ac->backupTopDir->s, attribPath->s, ac->backupNum)) ) {
            bpc_logErrf("bpc_attribCache_loadPath: bpc_attrib_dirRead(%s, %s) returned %d\n", ac->backupTopDir->s, attribPath->s, status);
        }
        /*
         * remove any extraneous BPC_FTYPE_DELETED file types
         */
	bpc_hashtable_iterate(&attr->dir.filesHT, (void*)bpc_attribCache_removeDeletedEntries, attr);
    }
    if ( bpc_hashtable_entryCount(&ac->attrHT) > BPC_ATTRIBCACHE_DIR_COUNT_MAX ) {
        bpc_attribCache_flush(ac, 0, NULL);
    }
    bpc_strBuf_free(attribPath);
    return attr;
}

static bpc_attribCache_dir *bpc_attribCache_loadInode(bpc_attribCache_info *ac, char *indexStr, ino_t inode)
{
    bpc_strBuf *attribPath = bpc_strBuf_new(), *attribDir = bpc_strBuf_new(), *attribFile = bpc_strBuf_new();
    bpc_strBuf *inodeDir, *fullAttribPath;
    bpc_attribCache_dir *attr;
    int attribPathLen, status;

    inodePath(ac, indexStr, attribDir, attribFile, inode);
    attribPathLen = bpc_strBuf_snprintf(attribPath, 0, "%s/%s", attribDir->s, attribFile->s);

    attr = bpc_hashtable_find(&ac->inodeHT, (uchar*)attribPath->s, attribPathLen, 1);

    if ( !attr || attr->key.key != attribPath->s ) {
        if ( attr ) attr->lruCnt = ac->cacheLruCnt++;
        bpc_strBuf_free(attribPath);
        bpc_strBuf_free(attribDir);
        bpc_strBuf_free(attribFile);
        return attr;
    }

    /*
     * new entry - read the attrib file
     */
    if ( !(attr->key.key = malloc(attribPathLen + 1)) ) {
        bpc_logErrf("bpc_attribCache_loadInode: can't allocate %d bytes\n", attribPathLen + 1);
        bpc_strBuf_free(attribPath);
        bpc_strBuf_free(attribDir);
        bpc_strBuf_free(attribFile);
        return NULL;
    }
    strcpy(attr->key.key, attribPath->s);
    bpc_attrib_dirInit(&attr->dir, ac->compress);
    attr->dirty  = 0;
    attr->dirOk  = 1;
    attr->lruCnt = ac->cacheLruCnt++;
    inodeDir = bpc_strBuf_new();
    fullAttribPath = bpc_strBuf_new();
    if ( ac->bkupMergeCnt > 0 ) {
        int i;

        /*
         * Merge multiple attrib files to create the "view" for this backup.
         * There is only one case here, v4, since v3 didn't have inodes. 
         */
        for ( i = 0 ; i < ac->bkupMergeCnt ; i++ ) {
            bpc_attrib_dir dir;
            ssize_t entrySize;
            char *entries, *fileName;

            bpc_strBuf_snprintf(inodeDir, 0, "%s/pc/%s/%d/%s", BPC_TopDir.s, ac->hostName->s, ac->bkupMergeList[i].num, attribDir->s);
            bpc_strBuf_snprintf(fullAttribPath, 0, "%s/%s", inodeDir->s, attribFile->s);

            bpc_attrib_dirInit(&dir, ac->bkupMergeList[i].compress);
            if ( (status = bpc_attrib_dirRead(&dir, inodeDir->s, attribFile->s, ac->bkupMergeList[i].num)) ) {
                STRUCT_STAT st;
                int attribDirExists = !stat(inodeDir->s, &st) && S_ISDIR(st.st_mode);
                if ( ac->bkupMergeList[i].version < 4 || !attribDirExists ) {
                     /*
                      * nothing to update here - keep going
                      */
                     bpc_attrib_dirDestroy(&dir);
                     continue;
                }
                bpc_logErrf("bpc_attribCache_loadInode: bpc_attrib_dirRead(%s/%s) returned %d\n", inodeDir->s, attribFile->s, status);
            }
            entrySize = bpc_attrib_getEntries(&dir, NULL, 0);
            if ( (entries = malloc(entrySize + 1)) && bpc_attrib_getEntries(&dir, entries, entrySize) == entrySize ) {
                for ( fileName = entries ; fileName < entries + entrySize ; fileName += strlen(fileName) + 1 ) {
                    bpc_attrib_file *file = bpc_attrib_fileGet(&dir, fileName, 0);
                    if ( !file ) continue;
                    if ( file->type == BPC_FTYPE_DELETED ) {
                        bpc_attrib_fileDeleteName(&attr->dir, fileName);
                    } else {
                        bpc_attrib_file *fileDest;

                        if ( !(fileDest = bpc_attrib_fileGet(&attr->dir, fileName, 1)) ) {
                            bpc_strBuf_free(attribPath);
                            bpc_strBuf_free(attribDir);
                            bpc_strBuf_free(attribFile);
                            bpc_strBuf_free(inodeDir);
                            bpc_strBuf_free(fullAttribPath);
                            return NULL;
                        }
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
                bpc_logErrf("bpc_attribCache_loadInode(%s): can't malloc %lu bytes for entries\n",
                                    fullAttribPath->s, (unsigned long)entrySize);
                if ( entries ) free(entries);
                bpc_attrib_dirDestroy(&dir);
                bpc_strBuf_free(attribPath);
                bpc_strBuf_free(attribDir);
                bpc_strBuf_free(attribFile);
                bpc_strBuf_free(inodeDir);
                bpc_strBuf_free(fullAttribPath);
                return NULL;
            }
            free(entries);
            bpc_attrib_dirDestroy(&dir);
        }
    } else {
        /*
         * non-merge case - read the single attrib file
         */
        bpc_strBuf_snprintf(inodeDir, 0, "%s/%s", ac->backupTopDir->s, attribDir->s);

        if ( (status = bpc_attrib_dirRead(&attr->dir, inodeDir->s, attribFile->s, ac->backupNum)) ) {
            bpc_logErrf("bpc_attribCache_loadInode: bpc_attrib_dirRead(%s/%s) returned %d\n", inodeDir->s, attribFile->s, status);
        }
    }
    if ( bpc_hashtable_entryCount(&ac->inodeHT) > BPC_ATTRIBCACHE_DIR_COUNT_MAX ) {
        bpc_attribCache_flush(ac, 0, NULL);
    }
    bpc_strBuf_free(attribPath);
    bpc_strBuf_free(attribDir);
    bpc_strBuf_free(attribFile);
    bpc_strBuf_free(inodeDir);
    bpc_strBuf_free(fullAttribPath);
    return attr;
}

bpc_attrib_file *bpc_attribCache_getFile(bpc_attribCache_info *ac, char *path, int allocate_if_missing, int dontReadInode)
{
    bpc_strBuf *fileName = bpc_strBuf_new();
    bpc_attribCache_dir *attr;
    bpc_attrib_file *file;

    if ( !(attr = bpc_attribCache_loadPath(ac, fileName, path)) ) {
        bpc_strBuf_free(fileName);
        return NULL;
    }
    attr->lruCnt = ac->cacheLruCnt++;
    if ( !(file = bpc_attrib_fileGet(&attr->dir, fileName->s, allocate_if_missing)) ) {
        bpc_strBuf_free(fileName);
        return NULL;
    }

    if ( allocate_if_missing && file->key.key == fileName->s ) {
        /*
         * new entry - initialize
         */
        bpc_attrib_fileInit(file, fileName->s, 0);
        file->compress = ac->compress;
    }
    bpc_strBuf_free(fileName);
    if ( dontReadInode || file->nlinks == 0 ) return file;

    return bpc_attribCache_getInode(ac, file->inode, allocate_if_missing);
}

int bpc_attribCache_setFile(bpc_attribCache_info *ac, char *path, bpc_attrib_file *file, int dontOverwriteInode)
{
    bpc_strBuf *fileName = bpc_strBuf_new();
    char indexStr[256];
    bpc_attribCache_dir *attr, *attrInode;
    bpc_attrib_file *fileDest;

    if ( !(attr = bpc_attribCache_loadPath(ac, fileName, path)) ) {
        bpc_strBuf_free(fileName);
        return -1;
    }
    attr->lruCnt = ac->cacheLruCnt++;
    file->compress = ac->compress;

    if ( !(fileDest = bpc_attrib_fileGet(&attr->dir, fileName->s, 1)) ) {
        bpc_strBuf_free(fileName);
        return -1;
    }

    if ( fileDest->key.key == fileName->s ) {
        /*
         * new entry - initialize
         */
        bpc_attrib_fileInit(fileDest, fileName->s, 0);
    }

    bpc_attrib_fileCopy(fileDest, file);
    attr->dirty = 1;
    bpc_strBuf_free(fileName);
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
    bpc_strBuf *fileName = bpc_strBuf_new();
    bpc_attribCache_dir *attr;

    if ( !(attr = bpc_attribCache_loadPath(ac, fileName, path)) ) {
        bpc_strBuf_free(fileName);
        return -1;
    }
    attr->lruCnt = ac->cacheLruCnt++;
    bpc_attrib_fileDeleteName(&attr->dir, fileName->s);
    attr->dirty = 1;
    bpc_strBuf_free(fileName);
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
    bpc_strBuf *fileName = bpc_strBuf_new(), *pathAppend = bpc_strBuf_new();

    /*
     * Append a fake file name so we actually open the directory's contents, not the directory entry one level up
     */
    bpc_strBuf_snprintf(pathAppend, 0, "%s/x", path);
    attr = bpc_attribCache_loadPath(ac, fileName, pathAppend->s);
    bpc_strBuf_free(fileName);
    bpc_strBuf_free(pathAppend);
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
    bpc_strBuf *fileName = bpc_strBuf_new(), *fullPath = bpc_strBuf_new();
    dirEntry_info info;
    ino_t inode = 0;

    /*
     * Append a fake file name so we actually open the directory's contents, not the directory entry one level up
     */
    if ( path[0] == '.' && path[1] == '\0' ) {
        if ( ac->currentDir->s[0] ) {
            bpc_strBuf_snprintf(fullPath, 0, "%s/x", ac->currentDir->s);
        } else {
            bpc_strBuf_strcpy(fullPath, 0, "/x");
        }
        attr = bpc_attribCache_loadPath(ac, fileName, fullPath->s);
    } else {
        bpc_strBuf_snprintf(fullPath, 0, "%s/x", path);
        attr = bpc_attribCache_loadPath(ac, fileName, fullPath->s);
    }
    bpc_strBuf_free(fileName);
    bpc_strBuf_free(fullPath);
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
        if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_attribCache_dirWrite: writing %s/%s with %d entries (oldDigest = 0x%02x%02x...)\n",
                                            info->ac->backupTopDir->s, (char*)attr->key.key, bpc_hashtable_entryCount(&attr->dir.filesHT),
                                            oldDigest ? oldDigest->digest[0] : 0, oldDigest ? oldDigest->digest[1] : 0);
        if ( (status = bpc_attrib_dirWrite(info->ac->deltaInfo, &attr->dir, info->ac->backupTopDir->s, attr->key.key, oldDigest)) ) {
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
    bpc_strBuf *attribPath = bpc_strBuf_new();

    info.all      = all;
    info.ac       = ac;
    if ( path ) {
        bpc_strBuf *pathDeep = bpc_strBuf_new(), *fileName = bpc_strBuf_new(), *dir = bpc_strBuf_new();

        bpc_strBuf_snprintf(pathDeep, 0, "%s/foo", path);
        splitPath(ac, dir, fileName, attribPath, pathDeep->s);
        info.path    = attribPath->s;
        info.pathLen = strlen(info.path);
        bpc_strBuf_free(pathDeep);
        bpc_strBuf_free(fileName);
        bpc_strBuf_free(dir);
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
        bpc_poolRefRequestFsck(ac->backupTopDir->s, 1);
    }
    bpc_strBuf_free(attribPath);
}

/*
 * Returns the full mangled path, given a file path.
 */
void bpc_attribCache_getFullMangledPath(bpc_attribCache_info *ac, bpc_strBuf *path, char *dirName, int backupNum)
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

    len = bpc_strBuf_snprintf(path, 0, "%s/pc/%s/%d/%s", BPC_TopDir.s, ac->hostName->s, backupNum, ac->shareName->s);
    if ( (dirName[0] == '/' && dirName[1] == '\0') || dirName[0] == '\0' ) {
        return;
    }
    bpc_strBuf_strcat(path, len++, "/");
    bpc_fileNameMangle(path, dirName, len);
}
