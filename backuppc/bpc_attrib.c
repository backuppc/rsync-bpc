/*
 * Routines for read/writing/managing file attributes
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
 * Type of attribute file.  This is saved as a magic number at the
 * start of the file.  This type is for V3 and earlier.
 */
#define BPC_ATTRIB_TYPE_UNIX    (0x17555555)

/*
 * super set of UNIX, including extended attribs and digest, for 4.x+
 */
#define BPC_ATTRIB_TYPE_XATTR   (0x17565353)

/*
 * starting in 4.x, attrib files in the pc backup tree are
 * just digests that give the location of the real attrib file
 * in the pool.  attrib files written in the pc backup tree
 * start with this magic number, followed by the digest.
 */
#define BPC_ATTRIB_TYPE_DIGEST  (0x17585451)

static char *FileType2Text[] = {
    "file",
    "hardlink",
    "symlink",
    "chardev",
    "blockdev",
    "dir",
    "fifo",
    "?",
    "socket",
    "?",
    "deleted",
};

/*
 * Ensure by default we use old-style "attrib" files for <= 4.0.0alpha3 compatibility.
 * Newer versions of BackupPC turn this off to use new attribute file naming.
 */
static int WriteOldStyleAttribFile = 1;
static int KeepOldAttribFiles      = 1;

void bpc_attrib_backwardCompat(int writeOldStyleAttribFile, int keepOldAttribFiles)
{
    if ( writeOldStyleAttribFile >= 0 ) WriteOldStyleAttribFile = writeOldStyleAttribFile;
    if ( keepOldAttribFiles >= 0 )      KeepOldAttribFiles = keepOldAttribFiles;
    if ( BPC_LogLevel >= 2 ) {
        bpc_logMsgf("bpc_attrib_backwardCompat: WriteOldStyleAttribFile = %d, KeepOldAttribFiles = %d\n",
                     WriteOldStyleAttribFile, KeepOldAttribFiles);
    }
}


#define CONV_BUF_TO_UINT32(buf)    ((buf)[0] << 24 | (buf)[1] << 16 | (buf)[2] << 8 | (buf)[3])

#define CONV_UINT32_TO_BUF(buf, val)   { *(buf)++ = ((val) >> 24) & 0xff;               \
                                         *(buf)++ = ((val) >> 16) & 0xff;               \
                                         *(buf)++ = ((val) >> 8)  & 0xff;               \
                                         *(buf)++ = ((val) >> 0)  & 0xff; }

/*
 * Note on xattr keys: they are treated as opaque strings of bytes, and the convention
 * is to include the '\0' byte termination in the keyLen (ie: it is strlen(key) + 1).
 */
bpc_attrib_xattr *bpc_attrib_xattrGet(bpc_attrib_file *file, void *key, int keyLen, int allocate_if_missing)
{
    return (bpc_attrib_xattr*)bpc_hashtable_find(&file->xattrHT, key, keyLen, allocate_if_missing);
}

void bpc_attrib_xattrDestroy(bpc_attrib_xattr *xattr)
{
    if ( xattr->key.key ) free(xattr->key.key);
    if ( xattr->value )   free(xattr->value);
}

int bpc_attrib_xattrDelete(bpc_attrib_file *file, void *key, int keyLen)
{
    bpc_attrib_xattr *xattr = bpc_hashtable_find(&file->xattrHT, key, keyLen, 0);

    if ( !xattr ) return -1;
    bpc_attrib_xattrDestroy(xattr);
    bpc_hashtable_nodeDelete(&file->xattrHT, xattr);
    return 0;
}

static void bpc_attrib_xattrDeleteNode(bpc_attrib_xattr *xattr, bpc_attrib_file *file)
{
    bpc_attrib_xattrDestroy(xattr);
    bpc_hashtable_nodeDelete(&file->xattrHT, xattr);
}

int bpc_attrib_xattrDeleteAll(bpc_attrib_file *file)
{
    bpc_hashtable_iterate(&file->xattrHT, (void*)bpc_attrib_xattrDeleteNode, file);
    return 0;
}

/*
 * returns >0 if the new value is the same as the current value.
 * returns 0  if the new value was set correctly
 * returns <0 on error.
 */
int bpc_attrib_xattrSetValue(bpc_attrib_file *file, void *key, int keyLen, void *value, uint32 valueLen)
{
    bpc_attrib_xattr *xattr = bpc_attrib_xattrGet(file, key, keyLen, 1);

    if ( !xattr->value ) {
        /*
         * new entry
         */
        if ( !(xattr->key.key = malloc(keyLen)) ) {
            bpc_logErrf("bpc_attrib_xattrSetValue: can't allocate %d bytes for key\n", keyLen);
            return -1;
        }
        memcpy(xattr->key.key, key, keyLen);
        xattr->key.keyLen = keyLen;
    } else {
        /*
         * existing entry - no need to recopy key.  If value array isn't big enough then create another.
         */
        if ( valueLen > xattr->valueLen ) {
            free(xattr->value);
            xattr->value = NULL;
        } else if ( valueLen == xattr->valueLen && !memcmp(xattr->value, value, valueLen) ) {
            /*
             * same value - no change
             */
            return 1;
        }
    }
    if ( !xattr->value && !(xattr->value = malloc(valueLen)) ) {
        bpc_logErrf("bpc_attrib_xattrSetValue: can't allocate %d bytes for value\n", valueLen);
        return -1;
    }
    memcpy(xattr->value, value, valueLen);
    xattr->valueLen = valueLen;
    return 0;
}

void bpc_attrib_xattrCopy(bpc_attrib_xattr *xattrSrc, bpc_attrib_file *fileDest)
{
    bpc_attrib_xattr *xattr;
    uchar *key   = (uchar*)malloc(xattrSrc->key.keyLen > 0 ? xattrSrc->key.keyLen : 1);
    uchar *value = (uchar*)malloc(xattrSrc->valueLen > 0 ? xattrSrc->valueLen : 1);

    if ( !key || !value ) {
        bpc_logErrf("bpc_attrib_xattrCopy: can't allocate %d,%d bytes\n", xattrSrc->key.keyLen + 1, xattrSrc->valueLen + 1);
        return;
    }

    memcpy(key, xattrSrc->key.key, xattrSrc->key.keyLen);
    memcpy(value, xattrSrc->value, xattrSrc->valueLen);

    xattr = bpc_attrib_xattrGet(fileDest, key, xattrSrc->key.keyLen, 1);

    if ( xattr->value ) {
        /*
         * Shouldn't be present, but if so clear it out and write the new key
         */
        bpc_attrib_xattrDestroy(xattr);
        xattr->key.key    = key;
        xattr->key.keyLen = xattrSrc->key.keyLen;
    }
    xattr->value    = value;
    xattr->valueLen = xattrSrc->valueLen;
}

int bpc_attrib_xattrCount(bpc_attrib_file *file)
{
    return bpc_hashtable_entryCount(&file->xattrHT);
}

typedef struct {
    char *list;
    ssize_t idx;
    ssize_t listLen;
    int ignoreRsyncACLs;
} xattrList_info;

static void bpc_attrib_xattrListKey(bpc_attrib_xattr *xattr, xattrList_info *info)
{
    if ( info->idx < 0 ) return;

    if ( info->ignoreRsyncACLs ) {
        static struct {
            char *str;
            unsigned int len;
        } ignoreKeys[] = {
            { "user.rsync.%aacl", sizeof("user.rsync.%aacl"), },    /* note: sizeof() includes the \0 terminator */
            { "user.rsync.%dacl", sizeof("user.rsync.%dacl"), },
        };
        uint i;

        for ( i = 0 ; i < sizeof(ignoreKeys) / sizeof(ignoreKeys[0]) ; i++ ) {
            if ( xattr->key.keyLen == ignoreKeys[i].len
                    && !memcmp(xattr->key.key, ignoreKeys[i].str, xattr->key.keyLen) ) {
                return;
            }
        }
    }
    if ( info->list ) {
        if ( info->idx + (signed)xattr->key.keyLen > info->listLen ) {
            info->idx = -1;
            return;
        }
        /*
         * keyLen already includes the \0 terminating byte
         */
        memcpy(info->list + info->idx, xattr->key.key, xattr->key.keyLen);
        info->idx += xattr->key.keyLen;
    } else {
        info->idx += xattr->key.keyLen;
    }
}

/*
 * Concatenate all the xattr keys, (which the caller has ensured are \0 terminated),
 * into a single string.  Return the number of bytes in the output string.
 * Returns -1 if listLen is too short to fit all the keys.
 * If list is NULL, instead returns the number of bytes required to store all the keys.
 */
size_t bpc_attrib_xattrList(bpc_attrib_file *file, char *list, size_t listLen, int ignoreRsyncACLs)
{
    xattrList_info info;

    info.list            = list;
    info.idx             = 0;
    info.listLen         = listLen;
    info.ignoreRsyncACLs = ignoreRsyncACLs;

    bpc_hashtable_iterate(&file->xattrHT, (void*)bpc_attrib_xattrListKey, &info);
    return info.idx;
}

void bpc_attrib_fileDestroy(bpc_attrib_file *file)
{
    if ( file->name) free(file->name);
    bpc_hashtable_iterate(&file->xattrHT, (void*)bpc_attrib_xattrDestroy, NULL);
    bpc_hashtable_destroy(&file->xattrHT);
}

/*
 * Return the attributes for the given file.
 * If allocate_if_missing == 0 and not present, then NULL is returned.
 * If allocate_if_missing != 0 and not present, then an empty struct is returned with the key filled in,
 * and file->name is NULL.
 */
bpc_attrib_file *bpc_attrib_fileGet(bpc_attrib_dir *dir, char *fileName, int allocate_if_missing)
{
    return bpc_hashtable_find(&dir->filesHT, (uchar*)fileName, strlen(fileName), allocate_if_missing);
}

/*
 * Initialize an empty file structure (ie: one returned by bpc_attrib_fileGet() that is empty)
 */
void bpc_attrib_fileInit(bpc_attrib_file *file, char *fileName, int xattrNumEntries)
{
    int fileNameLen = strlen(fileName);

    if ( file->name ) bpc_attrib_fileDestroy(file);
    file->name = (char*)malloc(fileNameLen + 1);
    if ( !file->name ) {
        bpc_logErrf("bpc_attrib_fileInit: can't allocate %d bytes for file name\n", fileNameLen + 1);
        return;
    }
    memcpy(file->name, fileName, fileNameLen + 1);
    file->isTemp  = 0;
    file->key.key = file->name;
    bpc_hashtable_create(&file->xattrHT, 16 + xattrNumEntries, sizeof(bpc_attrib_xattr));
}

/*
 * Copy all the attributes from fileSrc to fileDest.  fileDest should already have a
 * valid allocated fileName and allocated xattr hash.  The fileDest xattr hash is
 * emptied before the copy, meaning it is over written.
 *
 * If overwriteEmptyDigest == 0, an empty digest in fileSrc will not overwrite fileDest.
 */
void bpc_attrib_fileCopyOpt(bpc_attrib_file *fileDest, bpc_attrib_file *fileSrc, int overwriteEmptyDigest)
{
    if ( fileDest == fileSrc ) return;

    fileDest->type      = fileSrc->type;
    fileDest->compress  = fileSrc->compress;
    fileDest->mode      = fileSrc->mode;
    fileDest->isTemp    = fileSrc->isTemp;
    fileDest->uid       = fileSrc->uid;
    fileDest->gid       = fileSrc->gid;
    fileDest->nlinks    = fileSrc->nlinks;
    fileDest->mtime     = fileSrc->mtime;
    fileDest->size      = fileSrc->size;
    fileDest->inode     = fileSrc->inode;
    fileDest->backupNum = fileSrc->backupNum;
    if ( fileSrc->digest.len > 0 || overwriteEmptyDigest ) {
        fileDest->digest = fileSrc->digest;
    }
    bpc_hashtable_iterate(&fileDest->xattrHT, (void*)bpc_attrib_xattrDestroy, NULL);
    bpc_hashtable_erase(&fileDest->xattrHT);
    bpc_hashtable_iterate(&fileSrc->xattrHT, (void*)bpc_attrib_xattrCopy, fileDest);
}

/*
 * Copy all the attributes from fileSrc to fileDest.  fileDest should already have a
 * valid allocated fileName and allocated xattr hash.  The fileDest xattr hash is
 * emptied before the copy, meaning it is over written.
 */
void bpc_attrib_fileCopy(bpc_attrib_file *fileDest, bpc_attrib_file *fileSrc)
{
    if ( fileDest == fileSrc ) return;

    bpc_attrib_fileCopyOpt(fileDest, fileSrc, 1);
}

/*
 * Check if two file attribute structures are the same.  Returns 0 if they are the same.
 */
int bpc_attrib_fileCompare(bpc_attrib_file *file0, bpc_attrib_file *file1)
{
    uint idx = 0;

    if ( file0->type != file1->type
            || file0->compress   != file1->compress
            || file0->mode       != file1->mode
            || file0->uid        != file1->uid
            || file0->gid        != file1->gid
            || file0->nlinks     != file1->nlinks
            || file0->mtime      != file1->mtime
            || file0->size       != file1->size
            || file0->inode      != file1->inode
            || file0->digest.len != file1->digest.len
            || memcmp(file0->digest.digest, file1->digest.digest, file0->digest.len)
            || bpc_attrib_xattrCount(file0) != bpc_attrib_xattrCount(file1) ) {
        if ( BPC_LogLevel >= 9 ) bpc_logMsgf("bpc_attrib_fileCompare: %s %s differ\n", file0->name, file1->name);
        return 1;
    }
    while ( 1 ) {
        bpc_attrib_xattr *xattr0 = bpc_hashtable_nextEntry(&file0->xattrHT, &idx), *xattr1;
        if ( !xattr0 ) return 0;
        if ( !(xattr1 = bpc_attrib_xattrGet(file1, xattr0->key.key, xattr0->key.keyLen, 0)) ) return 1;
        if ( xattr0->valueLen != xattr1->valueLen || memcmp(xattr0->value, xattr1->value, xattr0->valueLen) ) return 1;
    }
}

void bpc_attrib_fileDeleteName(bpc_attrib_dir *dir, char *fileName)
{
    bpc_attrib_file *file = bpc_hashtable_find(&dir->filesHT, (uchar*)fileName, strlen(fileName), 0);

    if ( !file ) return;
    bpc_attrib_fileDestroy(file);
    bpc_hashtable_nodeDelete(&dir->filesHT, file);
}

int bpc_attrib_fileCount(bpc_attrib_dir *dir)
{
    return bpc_hashtable_entryCount(&dir->filesHT);
}

char *bpc_attrib_fileType2Text(int type)
{
    if ( type < 0 || type >= (int)(sizeof(FileType2Text) / sizeof(FileType2Text[0])) ) return "?";
    return FileType2Text[type];
}

void bpc_attrib_dirInit(bpc_attrib_dir *dir, int compressLevel)
{
    dir->digest.len = 0;
    dir->compress = compressLevel;
    bpc_hashtable_create(&dir->filesHT, 512, sizeof(bpc_attrib_file));
}

void bpc_attrib_dirDestroy(bpc_attrib_dir *dir)
{
    bpc_hashtable_iterate(&dir->filesHT, (void*)bpc_attrib_fileDestroy, NULL);
    bpc_hashtable_destroy(&dir->filesHT);
}

typedef struct {
    bpc_deltaCount_info *deltaInfo;
    int incr;
    unsigned int *inodeMax;
} fileRefCnt_info;

static void bpc_attrib_fileRefCount(bpc_attrib_file *file, fileRefCnt_info *info)
{
    if ( file->digest.len > 0 ) {
        char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];
        bpc_digest_digest2str(&file->digest, hexStr);
        if ( BPC_LogLevel >= 7 ) bpc_logMsgf("bpc_attrib_fileRefCount: file %s digest %s delta %d\n", file->name, hexStr, info->incr);
        bpc_poolRefDeltaUpdate(info->deltaInfo, file->compress, &file->digest, info->incr);
    }
    if ( info->inodeMax && file->inode > *info->inodeMax ) {
        *info->inodeMax = file->inode;
    }
}

/*
 * call refDeltaUpdate with incr (typically +/-1) for every entry in the directory,
 * as well as the dir itself.
 */
void bpc_attrib_dirRefCountInodeMax(bpc_deltaCount_info *deltaInfo, bpc_attrib_dir *dir, int incr, unsigned int *inodeMax)
{
    fileRefCnt_info info;

    info.deltaInfo = deltaInfo;
    info.incr      = incr;
    info.inodeMax  = inodeMax;
    bpc_hashtable_iterate(&dir->filesHT, (void*)bpc_attrib_fileRefCount, &info);
    if ( dir->digest.len > 0 ) {
        char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];
        bpc_digest_digest2str(&dir->digest, hexStr);
        if ( BPC_LogLevel >= 7 ) bpc_logMsgf("bpc_attrib_dirRefCount: attrib digest %s delta = %d\n", hexStr, incr);
        bpc_poolRefDeltaUpdate(deltaInfo, dir->compress, &dir->digest, incr);
    } else {
        if ( BPC_LogLevel >= 7 ) bpc_logMsgf("bpc_attrib_dirRefCount: no attrib digest -> no delta\n");
    }
}

/*
 * call refDeltaUpdate with incr (typically +/-1) for every entry in the directory,
 * as well as the dir itself.
 */
void bpc_attrib_dirRefCount(bpc_deltaCount_info *deltaInfo, bpc_attrib_dir *dir, int incr)
{
    bpc_attrib_dirRefCountInodeMax(deltaInfo, dir, incr, NULL);
}

typedef struct {
    char *entries;
    ssize_t entryIdx;
    ssize_t entrySize;
} dirEntry_info;

static void bpc_attrib_getDirEntry(bpc_attrib_file *file, dirEntry_info *info)
{
    ssize_t len = strlen(file->name) + 1;

    if ( info->entryIdx < 0 ) return;
    if ( info->entries ) {
        if ( info->entryIdx + len > info->entrySize ) {
            info->entryIdx = -1;
            return;
        }
        memcpy(info->entries + info->entryIdx, file->name, len);
    }
    info->entryIdx += len;
}

ssize_t bpc_attrib_getEntries(bpc_attrib_dir *dir, char *entries, ssize_t entrySize)
{
    dirEntry_info info;

    info.entries   = entries;
    info.entryIdx  = 0;
    info.entrySize = entrySize;

    bpc_hashtable_iterate(&dir->filesHT, (void*)bpc_attrib_getDirEntry, &info);
    return info.entryIdx;
}

void bpc_attrib_attribFilePath(char *path, char *dir, char *attribFileName)
{
    if ( !dir ) {
        snprintf(path, BPC_MAXPATHLEN, "%s", attribFileName);
    } else {
        snprintf(path, BPC_MAXPATHLEN, "%s/%s", dir, attribFileName ? attribFileName : "attrib");
    }
}

bpc_digest *bpc_attrib_dirDigestGet(bpc_attrib_dir *dir)
{
    return &dir->digest;
}

static int read_more_data(bpc_fileZIO_fd *fd, uchar *buf, size_t bufSize, size_t *nRead, uchar **bufPP, char *attribPath)
{
    int thisRead;
    /*
     * move the remaining part of the buffer down, and read more data
     */
    *nRead = (buf + *nRead) - *bufPP;
    memmove(buf, *bufPP, *nRead);
    *bufPP = buf;
    thisRead = bpc_fileZIO_read(fd, buf + *nRead, bufSize - *nRead);
    if ( thisRead < 0 ) {
        bpc_logErrf("bpc_attrib_dirRead: can't read more bytes from %s\n", attribPath);
        return -1;
    }
    *nRead += thisRead;
    return 0;
}

/*
 * Read variable-length unsigned integer in 7 bit chunks, LSB first.
 */
static int64 getVarInt(uchar **bufPP, uchar *bufEnd)
{
    int64 result = 0;
    uchar *bufP = *bufPP;
    int i = 0;

    while ( bufP < bufEnd ) {
        uchar c = *bufP++;
        result |= ((int64)(c & 0x7f)) << i;
        if ( !(c & 0x80) ) {
            *bufPP = bufP;
            return result;
        }
        i += 7;
    }
    /*
     * we ran out of data... make sure bufP is greater than bufEnd, since
     * returning it to be equal (ie: bufP) will be incorrectly interpreted as
     * meaning the integer correctly ended right at the end of the buffer.
     */
    *bufPP = bufEnd + 1;
    return result;
}

/*
 * V3 variable length integer read, MSB first, which is compatible with perl pack("w")
 */
static int64 getVarInt_v3(uchar **bufPP, uchar *bufEnd)
{
    int64 result = 0;
    uchar *bufP = *bufPP;

    while ( bufP < bufEnd ) {
        uchar c = *bufP++;
        result = (result << 7) | (c & 0x7f);
        if ( !(c & 0x80) ) {
            *bufPP = bufP;
            return result;
        }
    }
    /*
     * we ran out of data... make sure bufP is greater than bufEnd, since
     * returning it to be equal (ie: bufP) will be incorrectly interpreted as
     * meaning the integer correctly ended right at the end of the buffer.
     */
    *bufPP = bufEnd + 1;
    return result;
}

/*
 * Write variable-length unsigned integer in 7 bit chunks, LSB first
 */
static void setVarInt(uchar **bufPP, uchar *bufEnd, int64 value)
{
    uchar *bufP = *bufPP;

    if ( value < 0 ) {
        bpc_logErrf("setVarInt botch: got negative argument %ld; setting to 0\n", (long int)value);
        value = 0;
    }
    do {
        uchar c = value & 0x7f;
        value >>= 7;
        if ( value ) c |= 0x80;
        if ( bufP < bufEnd ) {
            *bufP++ = c;
        } else {
            bufP++;
        }
    } while ( value );
    *bufPP = bufP;
}

/*
 * Unpack the data in buf[] into the file structure, after the file name and xattr entry 
 * count have been extracted.  Returns next unused buffer location.
 *
 * If there isn't enough data to extract a complete file structure, the return value
 * will be greater than bufEnd.  You should gather more data and re-call the function.
 */
uchar *bpc_attrib_buf2file(bpc_attrib_file *file, uchar *buf, uchar *bufEnd, int xattrNumEntries)
{
    uchar *bufP   = buf;
    int i;

    file->type       = getVarInt(&bufP, bufEnd);
    file->mtime      = getVarInt(&bufP, bufEnd);
    file->mode       = getVarInt(&bufP, bufEnd);
    file->uid        = getVarInt(&bufP, bufEnd);
    file->gid        = getVarInt(&bufP, bufEnd);
    file->size       = getVarInt(&bufP, bufEnd);
    file->inode      = getVarInt(&bufP, bufEnd);
    file->compress   = getVarInt(&bufP, bufEnd);
    file->nlinks     = getVarInt(&bufP, bufEnd);
    file->digest.len = getVarInt(&bufP, bufEnd);
    file->isTemp     = 0;

    if ( file->digest.len > 0 && bufP + file->digest.len <= bufEnd ) {
        memcpy(file->digest.digest, bufP, file->digest.len);
    }
    bufP += file->digest.len;

    for ( i = 0 ; i < xattrNumEntries ; i++ ) {
        uint keyLen   = getVarInt(&bufP, bufEnd);
        uint valueLen = getVarInt(&bufP, bufEnd);

        if ( bufP + keyLen + valueLen <= bufEnd ) {
            bpc_attrib_xattrSetValue(file, bufP, keyLen, bufP + keyLen, valueLen);
        }
        bufP += keyLen + valueLen;
    }
    return bufP;
}

/*
 * Extract an entire packed file structure, starting with the fileName length varint.
 * Returns next unused buffer location.  It is assumed the file structure is already
 * initialized and has a valid fileName allocated, so we don't allocate it here.
 *
 * If there isn't enough data to extract a complete file structure, the return value
 * will be greater than bufEnd.  You should gather more data and re-call the function.
 * On certain errors, returns NULL;
 */
uchar *bpc_attrib_buf2fileFull(bpc_attrib_file *file, uchar *bufP, uchar *bufEnd)
{
    uint fileNameLen, xattrNumEntries;

    fileNameLen = getVarInt(&bufP, bufEnd);
    if ( fileNameLen > BPC_MAXPATHLEN - 1 ) {
        bpc_logErrf("bpc_attrib_buf2fileFull: got unreasonable file name length %d\n", fileNameLen);
        return NULL;
    }
    bufP += fileNameLen;
    xattrNumEntries = getVarInt(&bufP, bufEnd);
    bufP = bpc_attrib_buf2file(file, bufP, bufEnd, xattrNumEntries);
    return bufP;
}

/*
 * Read the attribute file at dirPath/attribFilePath and populate dir
 */
int bpc_attrib_dirRead(bpc_attrib_dir *dir, char *dirPath, char *attribFilePath, int backupNum)
{
    char attribPath[BPC_MAXPATHLEN];
    bpc_fileZIO_fd fd;
    size_t nRead;
    uint32 magic = 0;
    uchar buf[8 * 65536], *bufP;
    STRUCT_STAT st;
    char *p, *attribFileName;

    bpc_attrib_attribFilePath(attribPath, dirPath, attribFilePath);
    dir->digest.len = 0;

    /*
     * attribFileName points to the last portion of attribFilePath, or the whole
     * string if it doesn't contain '/'
     */
    if ( (attribFileName = strrchr(attribFilePath, '/')) ) {
        attribFileName++;
    } else {
        attribFileName = attribFilePath;
    }

    if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_attrib_dirRead(%s); dirPath = %s, attribFilePath = %s, attribFileName = %s\n",
                                         attribPath, dirPath, attribFilePath, attribFileName);

    if ( (p = strchr(attribFileName, '_')) && !stat(attribPath, &st) && S_ISREG(st.st_mode) ) {
        /*
         * Explicit path name to new-style attrib file, and it exists; extract digest
         */
        if ( !strcmp(p + 1, "0") ) return 0;
        bpc_digest_str2digest(&dir->digest, p + 1);
        if ( BPC_LogLevel >= 6 ) {
            char str[256];
            bpc_digest_digest2str(&dir->digest, str);
            bpc_logMsgf("bpc_attrib_dirRead: called with attrib file %s: digest = %s, len = %d\n",
                                              attribPath, str, dir->digest.len);
        }
        /*
         * Write new type attrib files (since we found a new-style one)
         */
	WriteOldStyleAttribFile = 0;
        magic = BPC_ATTRIB_TYPE_XATTR;
    } else if ( stat(attribPath, &st) || !S_ISREG(st.st_mode) || strchr(attribFileName, '_') ) {
        DIR *dirOs;
        struct dirent *dp;
        int attribFileNameLen = strlen(attribFileName);
        char attribDirPath[BPC_MAXPATHLEN];
        /*
         * Starting in 0.50, the attrib files are zero length with the digest encoded in
         * the file name, so there is no file just called "attrib".  Look in the directory
         * to find it.
         */
        strcpy(attribDirPath, attribPath);
        if ( (p = strrchr(attribDirPath, '/')) ) {
            *p = '\0';
        } else {
            strcpy(attribDirPath, ".");
        }
	if ( !(dirOs = opendir(attribDirPath)) ) {
            /*
             * This is a benign error - just return as though there is an empty attrib file
             */
            if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_attrib_dirRead: can't opendir %s (note: this is ok)\n", attribDirPath);
	    return 0;
	}
	while ( (dp = readdir(dirOs)) ) {
	    if ( strncmp(dp->d_name, attribFileName, attribFileNameLen) ) continue;
            p = dp->d_name + attribFileNameLen;
            if ( p[0] != '_' ) continue;
            p++;
	    if ( !strcmp(p, "0") ) {
                /*
                 * An empty attrib file is legit; just return with no entries
                 */
                if ( BPC_LogLevel >= 6 ) {
                    bpc_logMsgf("bpc_attrib_dirRead: Got empty attrib file %s\n", dp->d_name);
                }
		closedir(dirOs);
		return 0;
	    }
            bpc_digest_str2digest(&dir->digest, p);
            if ( BPC_LogLevel >= 6 ) {
                char str[256];
                bpc_digest_digest2str(&dir->digest, str);
                bpc_logMsgf("bpc_attrib_dirRead: Got attrib file %s: digest = %s, len = %d\n",
                                                  dp->d_name, str, dir->digest.len);
            }
            /*
             * Write new type attrib files (since we found a new-style one)
             */
            WriteOldStyleAttribFile = 0;
            break;
	}
	closedir(dirOs);
        if ( dir->digest.len == 0 ) return 0;
        magic = BPC_ATTRIB_TYPE_XATTR;
    } else {
        if ( bpc_fileZIO_open(&fd, attribPath, 0, dir->compress) ) {
            bpc_logErrf("bpc_attrib_dirRead: can't open %s\n", attribPath);
            return -1;
        }
        nRead = bpc_fileZIO_read(&fd, buf, sizeof(buf));
        if ( nRead == 0 ) {
            /*
             * an empty file is legit - this means an empty directory (ie: zero attrib entries).
             * indicate this with an empty digest and empty hash of entries.
             */
            bpc_fileZIO_close(&fd);
            if ( !strcmp(attribFileName, "attrib") ) {
                char attribPathTemp[BPC_MAXPATHLEN + 16];
                
                strcpy(attribPathTemp, attribPath);
                strcat(attribPathTemp, "_0");
                if ( rename(attribPath, attribPathTemp) ) {
                    bpc_logErrf("bpc_attrib_dirRead: rename of empty attrib file from %s to %s failed\n", attribPath, attribPathTemp);
                    return -1;
                } else if ( BPC_LogLevel >= 6 ) {
                    bpc_logMsgf("bpc_attrib_dirRead: renamed empty attrib file %s -> %s\n", attribPath, attribPathTemp);
                }
            }
            return 0;
        }
        if ( nRead < 4 ) {
            bpc_logErrf("bpc_attrib_dirRead: can't read at least 4 bytes from %s\n", attribPath);
            bpc_fileZIO_close(&fd);
            return -1;
        }
        magic = CONV_BUF_TO_UINT32(buf);
    }

    if ( magic == BPC_ATTRIB_TYPE_DIGEST ) {
        char attribPathNew[BPC_MAXPATHLEN];
        int fdNum;
        size_t digestLen = nRead - 4, attribPathLen = strlen(attribPath);

        if ( nRead < 20 ) {
            bpc_logErrf("bpc_attrib_dirRead: can't read at least 20 bytes from %s\n", attribPath);
            return -1;
        }
        bpc_fileZIO_close(&fd);
        if ( digestLen > sizeof(dir->digest.digest) ) digestLen = sizeof(dir->digest.digest);
        memcpy(dir->digest.digest, buf + 4, digestLen);
        dir->digest.len = digestLen;

        if ( !KeepOldAttribFiles ) {
            /*
             * replace the attrib file with a new-style attrib file where the digest is encoded
             * in a zero length file name
             */
            if ( attribPathLen + dir->digest.len * 2 + 2 >= sizeof(attribPathNew) ) {
                bpc_logErrf("bpc_attrib_dirRead: new digest path too long (%d, %d, %d)\n",
                                        attribPathLen, dir->digest.len, sizeof(attribPathNew));
                return -1;
            }
            strcpy(attribPathNew, attribPath);
            attribPathNew[attribPathLen++] = '_';
            bpc_digest_digest2str(&dir->digest, attribPathNew + attribPathLen);
            if ( (fdNum = open(attribPathNew, O_WRONLY | O_CREAT | O_TRUNC, 0660)) < 0 ) {
                bpc_logErrf("bpc_attrib_dirRead: can't open/create empty attrib file %s\n", attribPathNew);
                return -1;
            }
            close(fdNum);
            unlink(attribPath);
            if ( BPC_LogLevel >= 4 ) bpc_logMsgf("bpc_attrib_dirRead: replaced %s with %s\n",
                                                    attribPath, attribPathNew);
        }
    }

    if ( dir->digest.len > 0 ) {
        /*
         * Handle V4+ case - open the pool file directly
         * For V3, digest.len == 0 since we opened the attrib file above (it is stored hardlinked in the backup
         * directory; there is no digest)
         */
        bpc_digest_md52path(attribPath, dir->compress, &dir->digest);
        if ( bpc_fileZIO_open(&fd, attribPath, 0, dir->compress) ) {
            bpc_logErrf("bpc_attrib_dirRead: can't open %s\n", attribPath);
            return -1;
        }
        nRead = bpc_fileZIO_read(&fd, buf, sizeof(buf));
        if ( nRead < 4 ) {
            bpc_logErrf("bpc_attrib_dirRead: can't read at least 4 bytes from %s\n", attribPath);
            bpc_fileZIO_close(&fd);
            return -1;
        }
        magic = CONV_BUF_TO_UINT32(buf);
    }
    bufP = buf + 4;

    if ( magic == BPC_ATTRIB_TYPE_XATTR ) {
        int retry = 0;
        while ( bufP < buf + nRead ) {
            uint fileNameLen, xattrNumEntries;
            char *fileName;
            bpc_attrib_file *file;
            uchar *bufPsave = bufP;

            if ( nRead == sizeof(buf) && bufP > buf + nRead - 2 * BPC_MAXPATHLEN
                    && read_more_data(&fd, buf, sizeof(buf), &nRead, &bufP, attribPath) ) {
                bpc_fileZIO_close(&fd);
                return -1;
            }

            fileNameLen = getVarInt(&bufP, buf + nRead);
            if ( fileNameLen > BPC_MAXPATHLEN - 1 ) {
                bpc_logErrf("bpc_attrib_dirRead: got unreasonable file name length %d\n", fileNameLen);
                bpc_fileZIO_close(&fd);
                return -1;
            }

            /*
             * Save the fileName, but it's not NULL terminated yet.
             * After we consume the next varint, we can safely NULL-terminate
             * the fileName, which allows us to look up or create the file entry.
             */
            fileName = (char*)bufP;
            bufP    += fileNameLen;
            xattrNumEntries = getVarInt(&bufP, buf + nRead);
            fileName[fileNameLen] = '\0';

            file = bpc_attrib_fileGet(dir, fileName, 1);
            bpc_attrib_fileInit(file, fileName, xattrNumEntries);
            file->backupNum = backupNum;

            bufP = bpc_attrib_buf2file(file, bufP, buf + nRead, xattrNumEntries);
            if ( bufP > buf + nRead ) {
                /*
                 * Need to get more data and try again.  We have allocated file->name,
                 * and perhaps partially filled the xattr structure, which will be ok
                 * on the retry since the same structure will be used.
                 */
                if ( retry ) {
                    bpc_logErrf("bpc_attrib_dirRead: BOTCH: couldn't complete file conversion on retry (%ld,%ld,%ld)\n",
                                        bufP - buf, bufPsave - buf, nRead);
                    bpc_fileZIO_close(&fd);
                    return -1;
                }
                if ( BPC_LogLevel >= 7 ) bpc_logMsgf("bpc_attrib_dirRead: retrying file conversion\n");
                bufP = bufPsave;
                if ( read_more_data(&fd, buf, sizeof(buf), &nRead, &bufP, attribPath) ) {
                    bpc_fileZIO_close(&fd);
                    return -1;
                }
                retry = 1;
            } else {
                retry = 0;
            }
            if ( !retry && BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_attrib_dirRead(%s): Got file %s: type = %d, mode = 0%o, uid/gid = %d/%d, size = %d\n",
                                                  attribPath, file->name, file->type, file->mode, file->uid, file->gid, file->size);
        }
    } else if ( magic == BPC_ATTRIB_TYPE_UNIX ) {
        while ( bufP < buf + nRead ) {
            uint fileNameLen;
            char *fileName;
            bpc_attrib_file *file;
            int64 sizeDiv4GB;
            uint type;

            if ( nRead == sizeof(buf) && bufP > buf + nRead - 2 * BPC_MAXPATHLEN
                    && read_more_data(&fd, buf, sizeof(buf), &nRead, &bufP, attribPath) ) {
                bpc_fileZIO_close(&fd);
                return -1;
            }

            fileNameLen = getVarInt_v3(&bufP, buf + nRead);
            if ( fileNameLen > 2 * BPC_MAXPATHLEN - 16 ) {
                bpc_logErrf("bpc_attrib_dirRead: got unreasonable file name length %d\n", fileNameLen);
                bpc_fileZIO_close(&fd);
                return -1;
            }

            /*
             * Save the fileName, but it's not NULL terminated yet.
             * After we get the next data, we can safely NULL-terminate the fileName.
             */
            fileName = (char*)bufP;
            bufP    += fileNameLen;
            type     = getVarInt_v3(&bufP, buf + nRead);
            fileName[fileNameLen] = '\0';

            file = bpc_attrib_fileGet(dir, fileName, 1);
            bpc_attrib_fileInit(file, fileName, 0);

            file->type      = type;
            file->mode      = getVarInt_v3(&bufP, buf + nRead);
            file->uid       = getVarInt_v3(&bufP, buf + nRead);
            file->gid       = getVarInt_v3(&bufP, buf + nRead);
            sizeDiv4GB      = getVarInt_v3(&bufP, buf + nRead);
            file->size      = (sizeDiv4GB << 32) + getVarInt_v3(&bufP, buf + nRead);
            file->mtime     = CONV_BUF_TO_UINT32(bufP); bufP += 4;
            file->compress  = dir->compress;
            file->backupNum = backupNum;

            if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_attrib_dirRead(%s): Got v3 file %s: type = %d, mode = 0%o, uid/gid = %d/%d, size = %d\n",
                                                  attribPath, file->name, file->type, file->mode, file->uid, file->gid, file->size);
        }
    } else {
        bpc_logErrf("Unexpected magic number 0x%x read from %s\n", magic, attribPath);
        return -1;
    }
    /* TODO: make sure we are at EOF? */
    bpc_fileZIO_close(&fd);
    return 0;
}

typedef struct {
    uchar *bufP;
    uchar *bufEnd;
} buf_info;

typedef struct {
    bpc_poolWrite_info fd;
    uchar buf[4 * 65536];
    uchar *bufP;
} write_info;

static void write_file_flush(write_info *info)
{
    if ( info->bufP > info->buf ) {
        if ( BPC_LogLevel >= 7 ) bpc_logMsgf("write_file_flush: writing %lu bytes to pool\n", (unsigned long)(info->bufP - info->buf));
        bpc_poolWrite_write(&info->fd, info->buf, info->bufP - info->buf);
    }
    info->bufP = info->buf;
}

static void bpc_attrib_xattrWrite(bpc_attrib_xattr *xattr, buf_info *info)
{
    setVarInt(&info->bufP, info->bufEnd, xattr->key.keyLen);
    setVarInt(&info->bufP, info->bufEnd, xattr->valueLen);

    if ( info->bufP + xattr->key.keyLen <= info->bufEnd ) {
        memcpy(info->bufP, xattr->key.key, xattr->key.keyLen);
    }
    info->bufP += xattr->key.keyLen;

    if ( info->bufP + xattr->valueLen <= info->bufEnd ) {
        memcpy(info->bufP, xattr->value, xattr->valueLen);
    }
    info->bufP += xattr->valueLen;
}

/*
 * Write a file structure to the memory buffer.  Returns the next unused buffer
 * pointer.  If the buffer is exhausted, no data is written past the buffer end,
 * Therefore, if the return value is greater than bufEnd, then the conversion
 * failed to fit.  The routine can be called again with at least (bufP - buf)
 * bytes allocated.
 */
uchar *bpc_attrib_file2buf(bpc_attrib_file *file, uchar *buf, uchar *bufEnd)
{
    uchar *bufP = buf;
    size_t fileNameLen = strlen(file->name);
    uint xattrEntryCnt = bpc_hashtable_entryCount(&file->xattrHT);
    buf_info info;

    setVarInt(&bufP, bufEnd, fileNameLen);
    if ( bufP + fileNameLen < bufEnd ) {
        memcpy(bufP, file->name, fileNameLen);
    }
    bufP += fileNameLen;

    setVarInt(&bufP, bufEnd, xattrEntryCnt);
    setVarInt(&bufP, bufEnd, file->type);
    setVarInt(&bufP, bufEnd, file->mtime);
    setVarInt(&bufP, bufEnd, file->mode);
    setVarInt(&bufP, bufEnd, file->uid);
    setVarInt(&bufP, bufEnd, file->gid);
    setVarInt(&bufP, bufEnd, file->size);
    setVarInt(&bufP, bufEnd, file->inode);
    setVarInt(&bufP, bufEnd, file->compress);
    setVarInt(&bufP, bufEnd, file->nlinks);
    setVarInt(&bufP, bufEnd, file->digest.len);

    if ( bufP + file->digest.len <= bufEnd ) {
        memcpy(bufP, file->digest.digest, file->digest.len);
    }
    bufP += file->digest.len;

    info.bufEnd = bufEnd;
    info.bufP   = bufP;
    bpc_hashtable_iterate(&file->xattrHT, (void*)bpc_attrib_xattrWrite, &info);

    return info.bufP;
}

static void bpc_attrib_fileWrite(bpc_attrib_file *file, write_info *info)
{
    uchar *bufP;

    if ( file->isTemp ) {
        if ( BPC_LogLevel >= 6 ) bpc_logMsgf("Skipping temp file %s: type = %d, mode = 0%o, uid/gid = %lu/%lu, size = %lu, inode = %lu, nlinks = %d, digest = 0x%02x%02x%02x..., bufUsed = %lu\n",
                file->name, file->type, file->mode,
                (unsigned long)file->uid, (unsigned long)file->gid,
                (unsigned long)file->size, (unsigned long)file->inode, file->nlinks,
                file->digest.digest[0], file->digest.digest[1], file->digest.digest[2],
                (unsigned long)(info->bufP - info->buf));
        return;
    }
    bufP = bpc_attrib_file2buf(file, info->bufP, info->buf + sizeof(info->buf));
    if ( BPC_LogLevel >= 6 ) bpc_logMsgf("Wrote file %s: type = %d, mode = 0%o, uid/gid = %lu/%lu, size = %lu, inode = %lu, nlinks = %d, digest = 0x%02x%02x%02x..., bufUsed = %lu\n",
                file->name, file->type, file->mode,
                (unsigned long)file->uid, (unsigned long)file->gid,
                (unsigned long)file->size, (unsigned long)file->inode, file->nlinks,
                file->digest.digest[0], file->digest.digest[1], file->digest.digest[2],
                (unsigned long)(info->bufP - info->buf));

    if ( bufP <= info->buf + sizeof(info->buf) ) {
        /*
         * it fit into the buffer
         */
        info->bufP = bufP;
        return;
    }
    /*
     * we overflowed the buffer - flush and try again
     */
    write_file_flush(info);
    bufP = bpc_attrib_file2buf(file, info->bufP, info->buf + sizeof(info->buf));
    if ( bufP <= info->buf + sizeof(info->buf) ) {
        info->bufP = bufP;
        return;
    }
    bpc_logErrf("bpc_attrib_fileWrite: BOTCH: can't fit file into buffer (%ld, %ld)\n", bufP - info->buf, sizeof(info->buf));
}

/*
 * Pre 0.50 attribute writing.  Writes a small file that contains the file hash of the attrib file
 */
static int bpc_attrib_dirWriteOld(bpc_deltaCount_info *deltaInfo, bpc_attrib_dir *dir,
                                  char *dirPath, char *attribFileName, bpc_digest *oldDigest)
{
    char attribPath[BPC_MAXPATHLEN], attribPathTemp[BPC_MAXPATHLEN];
    bpc_fileZIO_fd fd;
    bpc_digest digest;
    int status;
    OFF_T poolFileSize;
    int errorCnt;
    static write_info info;
    char *p;

    bpc_attrib_attribFilePath(attribPath, dirPath, attribFileName);
    if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_attrib_dirWriteOld(%s)\n", attribPath);
    snprintf(attribPathTemp, BPC_MAXPATHLEN, "%s.%d", attribPath, getpid());
    if ( (p = strrchr(attribPathTemp, '/')) ) {
        *p = '\0';
        if ( bpc_path_create(attribPathTemp) ) return -1;
        *p = '/';
    }

    if ( bpc_hashtable_entryCount(&dir->filesHT) == 0 ) {
        int fdNum;
        /*
         * Empty directory - we just generate an empty attrib file, which we don't pool
         */
        if ( (fdNum = open(attribPathTemp, O_WRONLY | O_CREAT | O_TRUNC, 0660)) < 0 ) {
            bpc_logErrf("bpc_attrib_dirWrite: can't open/create raw %s for writing\n", attribPathTemp);
            return -1;
        }
        close(fdNum);
        if ( rename(attribPathTemp, attribPath) ) {
            bpc_logErrf("bpc_attrib_dirWrite: rename from %s to %s failed\n", attribPathTemp, attribPath);
            return -1;
        }
        if ( oldDigest ) bpc_poolRefDeltaUpdate(deltaInfo, dir->compress, oldDigest, -1);
	dir->digest.len = 0;
        return 0;
    }

    info.bufP = info.buf;
    CONV_UINT32_TO_BUF(info.bufP, BPC_ATTRIB_TYPE_XATTR);

    bpc_poolWrite_open(&info.fd, dir->compress, NULL);
    bpc_hashtable_iterate(&dir->filesHT, (void*)bpc_attrib_fileWrite, &info);
    write_file_flush(&info);
    bpc_poolWrite_close(&info.fd, &status, &digest, &poolFileSize, &errorCnt);

    if ( errorCnt ) return -1;

    /*
     * Now write the small atttib file, which just contains a magic number and the digest
     */
    if ( bpc_fileZIO_open(&fd, attribPathTemp, 1, dir->compress) ) {
        bpc_logErrf("bpc_attrib_dirWrite: can't open/create %s for writing\n", attribPathTemp);
        return -1;
    }
    info.bufP = info.buf;
    CONV_UINT32_TO_BUF(info.bufP, BPC_ATTRIB_TYPE_DIGEST);
    if ( digest.len > 0 ) {
        memcpy(info.bufP, digest.digest, digest.len);
        info.bufP += digest.len;
    }
    if ( bpc_fileZIO_write(&fd, info.buf, info.bufP - info.buf) < 0 ) {
        bpc_logErrf("bpc_attrib_dirWrite: can't write to %s\n", attribPathTemp);
        bpc_fileZIO_close(&fd);
        return -1;
    }
    bpc_fileZIO_close(&fd);
    if ( rename(attribPathTemp, attribPath) ) {
        bpc_logErrf("bpc_attrib_dirWrite: rename from %s to %s failed\n", attribPathTemp, attribPath);
        return -1;
    }
    if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_attrib_dirWrite: new attrib digest = 0x%02x%02x%02x..., oldDigest = 0x%02x%02x...\n",
                digest.digest[0], digest.digest[1], digest.digest[2],
                oldDigest ? oldDigest->digest[0] : 0x0, oldDigest ? oldDigest->digest[1] : 0x0);

    if ( oldDigest ) bpc_poolRefDeltaUpdate(deltaInfo, dir->compress, oldDigest, -1);
    bpc_poolRefDeltaUpdate(deltaInfo, dir->compress, &digest, 1);

    /*
     * update with the new digest
     */
    memcpy(&dir->digest, &digest, sizeof(digest));

    return 0;
}

int bpc_attrib_dirWrite(bpc_deltaCount_info *deltaInfo, bpc_attrib_dir *dir, char *dirPath, char *attribFileName, bpc_digest *oldDigest)
{
    char attribPath[BPC_MAXPATHLEN], attribPathTemp[BPC_MAXPATHLEN], *baseAttribFileName;
    bpc_digest digest;
    int status;
    OFF_T poolFileSize;
    int errorCnt;
    static write_info info;
    char *p;
    int fdNum;
    size_t attribPathLen, baseAttribFileNameLen;

    if ( WriteOldStyleAttribFile ) return bpc_attrib_dirWriteOld(deltaInfo, dir, dirPath, attribFileName, oldDigest);

    /*
     * baseAttribFileName points to the last portion of attribFileName, or the whole
     * string if it doesn't contain '/'
     */
    if ( (baseAttribFileName = strrchr(attribFileName, '/')) ) {
        baseAttribFileName++;
    } else {
        baseAttribFileName = attribFileName;
    }
    baseAttribFileNameLen = strlen(baseAttribFileName);

    bpc_attrib_attribFilePath(attribPath, dirPath, attribFileName);
    if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_attrib_dirWrite(%s): dirPath = %s, attribFileName = %s, baseAttribFileName = %s\n",
                                          attribPath, dirPath, attribFileName, baseAttribFileName);
    snprintf(attribPathTemp, BPC_MAXPATHLEN, "%s.%d", attribPath, getpid());
    if ( (p = strrchr(attribPathTemp, '/')) ) {
        *p = '\0';
        if ( bpc_path_create(attribPathTemp) ) return -1;
        *p = '/';
    }
    attribPathLen = strlen(attribPath);

    if ( bpc_hashtable_entryCount(&dir->filesHT) > 0 ) {
        /*
         * Write the attribute file to the pool
         */
        info.bufP = info.buf;
        CONV_UINT32_TO_BUF(info.bufP, BPC_ATTRIB_TYPE_XATTR);

        bpc_poolWrite_open(&info.fd, dir->compress, NULL);
        bpc_hashtable_iterate(&dir->filesHT, (void*)bpc_attrib_fileWrite, &info);
        write_file_flush(&info);
        bpc_poolWrite_close(&info.fd, &status, &digest, &poolFileSize, &errorCnt);

        if ( errorCnt ) return -1;

        /*
         * Starting in 0.50, the attrib file is always empty (so it takes no extra blocks)
         * and we simply include the digest in the file name by appending the hex digits.
         *
         * An empty attrib file is simply "attrib_0", and a legacy attrib file (pre <0.50)
         * is "attrib".
         */
        if ( attribPathLen + digest.len * 2 + 2 >= sizeof(attribPath) ) {
            bpc_logErrf("bpc_attrib_dirWrite: path too long (%d, %d, %d)\n", strlen(attribPath), digest.len, sizeof(attribPath));
            return -1;
        }
        attribPath[attribPathLen++] = '_';
        bpc_digest_digest2str(&digest, attribPath + attribPathLen);
    } else {
        digest.len = 0;
        attribPath[attribPathLen++] = '_';
        strcpy(attribPath + attribPathLen, "0");
    }
    
    /*
     * Now create an empty attrib file
     */
    if ( (fdNum = open(attribPathTemp, O_WRONLY | O_CREAT | O_TRUNC, 0660)) < 0 ) {
        bpc_logErrf("bpc_attrib_dirWrite: can't open/create raw %s for writing\n", attribPathTemp);
        return -1;
    }
    close(fdNum);
    if ( rename(attribPathTemp, attribPath) ) {
        bpc_logErrf("bpc_attrib_dirWrite: rename from %s to %s failed\n", attribPathTemp, attribPath);
        return -1;
    }
    if ( BPC_LogLevel >= 5 ) bpc_logMsgf("bpc_attrib_dirWrite: created new attrib file %s\n", attribPath);

    if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_attrib_dirWrite: new attrib digest = 0x%02x%02x%02x..., oldDigest = 0x%02x%02x...\n",
                digest.digest[0], digest.digest[1], digest.digest[2],
                oldDigest ? oldDigest->digest[0] : 0x0, oldDigest ? oldDigest->digest[1] : 0x0);
    bpc_poolRefDeltaUpdate(deltaInfo, dir->compress, &digest, 1);

    if ( oldDigest ) {
        if ( !bpc_digest_compare(&digest, oldDigest) ) {
            if ( BPC_LogLevel >= 2 ) bpc_logMsgf("bpc_attrib_dirWrite: old attrib has same digest; no changes to ref counts\n");
            return 0;
        }
        if ( attribPathLen + oldDigest->len * 2 + 2 >= sizeof(attribPath) ) {
            bpc_logErrf("bpc_attrib_dirWrite: oldDigest path too long (%d, %d, %d)\n", strlen(attribPath), oldDigest->len, sizeof(attribPath));
            return -1;
        }
        strcpy(attribPathTemp, attribPath);
        if ( oldDigest->len > 0 ) {
            bpc_poolRefDeltaUpdate(deltaInfo, dir->compress, oldDigest, -1);
            bpc_digest_digest2str(oldDigest, attribPathTemp + attribPathLen);
        } else {
            strcpy(attribPathTemp + attribPathLen, "0");
        }
        if ( !unlink(attribPathTemp) ) {
            if ( BPC_LogLevel >= 5 ) bpc_logMsgf("bpc_attrib_dirWrite: removed old attrib file %s\n", attribPathTemp);
        } else {
            DIR *dirOs;
            struct dirent *dp;
            char deletePath[BPC_MAXPATHLEN];

            /*
             * Scan the directory and remove any other attribute files that have the
             * same root.
             */
            if ( !(p = strrchr(attribPath, '/')) ) {
                bpc_logErrf("bpc_attrib_dirWrite: can't find a '/' in %s\n", attribPath);
                return -1;
            }
            *p++ = '\0';
            if ( !(dirOs = opendir(attribPath)) ) {
                bpc_logErrf("bpc_attrib_dirWrite: can't opendir %s\n", attribPath);
                return -1;
            }
            while ( (dp = readdir(dirOs)) ) {
                if ( strncmp(dp->d_name, baseAttribFileName, baseAttribFileNameLen) || !strcmp(dp->d_name, p) ) continue;
                snprintf(deletePath, sizeof(deletePath), "%s/%s", attribPath, dp->d_name);
                unlink(deletePath);
                if ( BPC_LogLevel >= 5 ) bpc_logMsgf("bpc_attrib_dirWrite: removed other old attrib file %s\n", deletePath);
            }
            closedir(dirOs);
        }
    }

    /*
     * update with the new digest
     */
    memcpy(&dir->digest, &digest, sizeof(digest));

    return 0;
}
