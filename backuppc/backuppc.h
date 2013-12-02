/*
 * Definitions for BackupPC libraries.
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

#ifndef _BACKUPPC_H_

#define _BACKUPPC_H_

#include <rsync.h>
#include <zlib.h>

#define BPC_MAXPATHLEN          (2 * MAXPATHLEN)

extern char BPC_PoolDir[];
extern char BPC_CPoolDir[];
extern char BPC_PoolDir3[];
extern char BPC_CPoolDir3[];
extern char BPC_TopDir[];
extern int BPC_HardLinkMax;
extern int BPC_PoolV3Enabled;
extern int BPC_TmpFileUnique;
extern int BPC_LogLevel;

/*
 * Maximum length of a digest - 16 bytes for MD5, but 4 bytes of collision counting
 */
#define BPC_DIGEST_LEN_MAX      20

#define uint64  unsigned int64

typedef struct {
    uchar digest[BPC_DIGEST_LEN_MAX];
    int len;
} bpc_digest;

/*
 * Simple hash table functions.
 *
 * Any structure stored in a hash table should start with a bpc_hashtable_key entry for the key.
 */
typedef struct {
    void *nodes;
    uint32 nodeSize;
    uint32 size;
    uint32 entries;     /* total number of user entries */
    uint32 entriesDel;  /* number of entries flagged as deleted */
} bpc_hashtable;

typedef struct {
    void *key;          /* a NULL key means this node is empty or deleted */
    uint32 keyLen;      /* with a NULL key, a zero value means empty; non-zero means deleted */
    uint32 keyHash;
} bpc_hashtable_key;

void bpc_hashtable_create(bpc_hashtable *tbl, uint32 size, uint32 nodeSize);
void bpc_hashtable_destroy(bpc_hashtable *tbl);
void bpc_hashtable_erase(bpc_hashtable *tbl);
uint32 bpc_hashtable_hash(uchar *key, uint32 keyLen);
void *bpc_hashtable_find(bpc_hashtable *tbl, unsigned char *key, unsigned int keyLen, int allocate_if_missing);
void bpc_hashtable_growSize(bpc_hashtable *tbl, uint32 newSize);
void bpc_hashtable_nodeDelete(bpc_hashtable *tbl, void *node);
void bpc_hashtable_iterate(bpc_hashtable *tbl, void (*callback)(void*, void*), void *arg1);
void *bpc_hashtable_nextEntry(bpc_hashtable *tbl, uint *idx);
int bpc_hashtable_entryCount(bpc_hashtable *tbl);

/*
 * Reference counting
 */
typedef struct {
    bpc_hashtable ht;
    int initDone;
} bpc_refCount_info;

void bpc_poolRefInit(bpc_refCount_info *info, int entryCnt);
void bpc_poolRefDestroy(bpc_refCount_info *info);
void bpc_poolRefSet(bpc_refCount_info *info, bpc_digest *digest, int32 count);
int bpc_poolRefDelete(bpc_refCount_info *info, bpc_digest *digest);
int bpc_poolRefGet(bpc_refCount_info *info, bpc_digest *digest, int32 *count);
int bpc_poolRefIncr(bpc_refCount_info *info, bpc_digest *digest, int32 delta);
int bpc_poolRefIterate(bpc_refCount_info *info, bpc_digest *digest, int32 *count, uint *idx);
void bpc_poolRefCountPrint(bpc_refCount_info *info);
int bpc_poolRefFileWrite(bpc_refCount_info *info, char *fileName);
int bpc_poolRefFileRead(bpc_refCount_info *info, char *fileName);
void bpc_poolRefRequestFsck(char *hostDir, int ext);

void bpc_poolRefDeltaFileInit(char *hostDir);
uint32 bpc_poolRefDeltaFileFlush(void);
void bpc_poolRefDeltaUpdate(int compress, bpc_digest *digest, int32 count);
void bpc_poolRefDeltaPrint(void);

/*
 * Compressed file IO.  A compressed file descriptor contains a buffer for compressed data.
 */
typedef struct {
    z_stream strm;
    char *buf;
    size_t bufSize;
    int fd;
    int first;
    int write;
    int eof;
    int error;
    int compressLevel;
    int writeTeeStderr;
    /*
     * readLine buffer
     */
    char  *lineBuf;
    size_t lineBufSize;
    size_t lineBufLen;
    size_t lineBufIdx;
    int lineBufEof;
} bpc_fileZIO_fd;

int bpc_fileZIO_open(bpc_fileZIO_fd *fd, char *fileName, int writeFile, int compressLevel);
int bpc_fileZIO_fdopen(bpc_fileZIO_fd *fd, FILE *stream, int writeFile, int compressLevel);
void bpc_fileZIO_writeTeeStderr(bpc_fileZIO_fd *fd, int tee);
ssize_t bpc_fileZIO_read(bpc_fileZIO_fd *fd, uchar *buf, size_t nRead);
ssize_t bpc_fileZIO_write(bpc_fileZIO_fd *fd, uchar *buf, size_t nWrite);
int bpc_fileZIO_readLine(bpc_fileZIO_fd *fd, char **str, size_t *strLen);
int bpc_fileZIO_close(bpc_fileZIO_fd *fd);
int bpc_fileZIO_rewind(bpc_fileZIO_fd *fd);

#define BPC_POOL_WRITE_BUF_SZ             (8 * 1048576)     /* 8 MB - must be at least 1MB so the V3 digest calculation can occur */
#define BPC_POOL_WRITE_CONCURRENT_MATCH   (16)              /* number of pool files we concurrently match */

typedef struct _bpc_candidate_file {
    bpc_digest digest;
    OFF_T fileSize;
    int v3File;
    char fileName[BPC_MAXPATHLEN];
    struct _bpc_candidate_file *next;
} bpc_candidate_file;

typedef struct {
    bpc_fileZIO_fd fd;
    int used;
    int v3File;
    OFF_T fileSize;
    bpc_digest digest;
    char fileName[BPC_MAXPATHLEN];
} bpc_candidate_match;

typedef struct {
    int compress;
    int state;
    int eof;
    int retValue;
    int retryCnt;
    OFF_T fileSize;
    OFF_T poolFileSize;
    bpc_digest digest;
    bpc_digest digest_v3;
    md_context md5;
    /*
     * Set of active potential file matches.  All files match up to matchPosn.
     */
    OFF_T matchPosn;
    bpc_candidate_match match[BPC_POOL_WRITE_CONCURRENT_MATCH];
    bpc_candidate_file *candidateList;
    /*
     * When we first build the candidate match list, we remember where the first
     * zero-length file is (if any), and the next open slot.  If these change
     * before we insert a new file, we know to try again (since someone probably
     * won a race to get there first).
     */
    int digestExtZeroLen, digestExtOpen;
    /*
     * Temporary output file if the in-memory buffer is too small
     */
    int fdOpen;
    bpc_fileZIO_fd fd;
    char tmpFileName[BPC_MAXPATHLEN];
    /*
     * Error count
     */
    int errorCnt;
    /*
     * Initial file buffer - used if the entire file fits, or otherwise keeps the first 1MB
     * of the file so we can compute the V3 digest.  If we have the entire file in memory
     * then fileWritten == 0.
     *
     * This buffer is allocated to be size BPC_POOL_WRITE_BUF_SZ on open() and freed on close().
     */
    uint32 bufferIdx;
    uchar *buffer;
} bpc_poolWrite_info;

int bpc_poolWrite_open(bpc_poolWrite_info *info, int compress, bpc_digest *digest);
int bpc_poolWrite_write(bpc_poolWrite_info *info, uchar *data, size_t dataLen);
int bpc_poolWrite_createPoolDir(bpc_poolWrite_info *info, bpc_digest *digest);
void bpc_poolWrite_close(bpc_poolWrite_info *info, int *match, bpc_digest *digest, OFF_T *poolFileSize, int *errorCnt);
void bpc_poolWrite_cleanup(bpc_poolWrite_info *info);
void bpc_poolWrite_repeatPoolWrite(bpc_poolWrite_info *info, char *fileName);
int bpc_poolWrite_copyToPool(bpc_poolWrite_info *info, char *poolPath, char *fileName);
void bpc_poolWrite_addToPool(bpc_poolWrite_info *info, char *fileName, int v3PoolFile);
int bpc_poolWrite_unmarkPendingDelete(char *poolPath);

/*
 * General library routines
 */
void bpc_lib_conf_init(char *topDir, int hardLinkMax, int poolV3Enabled, int logLevel);
void bpc_lib_setTmpFileUnique(int val);
int bpc_lib_setLogLevel(int logLevel);
void bpc_byte2hex(char *outStr, int byte);
void bpc_digest_buffer2MD5(bpc_digest *digest, uchar *buffer, size_t bufferLen);
void bpc_digest_append_ext(bpc_digest *digest, uint32 ext);
void bpc_digest_digest2str(bpc_digest *digest, char *hexStr);
int bpc_digest_compare(bpc_digest *digest1, bpc_digest *digest2);
void bpc_digest_md52path(char *path, int compress, bpc_digest *digest);
void bpc_digest_md52path_v3(char *path, int compress, bpc_digest *digest);
void bpc_digest_buffer2MD5_v3(bpc_digest *digest, uchar *buffer, size_t bufferLen);
void bpc_fileNameEltMangle(char *path, int pathSize, char *pathUM);
void bpc_fileNameMangle(char *path, int pathSize, char *pathUM);
void bpc_logMsgf(char *fmt, ...);
void bpc_logErrf(char *fmt, ...);
void bpc_logMsgGet(char **mesg, size_t *mesgLen);
void bpc_logMsgErrorCntGet(unsigned long *errorCnt);
void bpc_logMsgCBSet(void (*cb)(int errFlag, char *mesg, size_t mesgLen));

/*
 * Directory operations
 */
int bpc_path_create(char *path);
int bpc_path_remove(char *path, int compress);
int bpc_path_refCountAll(char *path, int compress);
int bpc_lockRangeFd(int fd, OFF_T offset, OFF_T len, int block);
int bpc_unlockRangeFd(int fd, OFF_T offset, OFF_T len);
int bpc_lockRangeFile(char *lockFile, OFF_T offset, OFF_T len, int block);
void bpc_unlockRangeFile(int lockFd);

/*
 * File attribs
 */
typedef struct {
    bpc_hashtable_key key;
    void *value;
    uint32 valueLen;
} bpc_attrib_xattr;

typedef struct {
    bpc_hashtable_key key;
    char *name;
    ushort type;
    ushort compress;
    /*
     * isTemp is set if this is a temporary attribute entry (eg: mkstemp), that
     * doesn't have referencing counting for the digest.  Therefore, when a
     * temporary file is created or deleted, there is no change to the
     * reference counts.
     */
    ushort isTemp;
    uint32 mode;
    uint32 uid;
    uint32 gid;
    uint32 nlinks;
    time_t mtime;
    OFF_T size;
    ino_t inode;
    int32 backupNum;
    bpc_digest digest;
    /*
     * hash table of bpc_attrib_xattr entries, indexed by xattr key
     */
    bpc_hashtable xattrHT;
} bpc_attrib_file;

/*
 * A directory is a hash table of file attributes, indexed by file name
 */
typedef struct {
    bpc_digest digest;
    ushort compress;
    /*
     * hash table of bpc_attrib_file entries, indexed by file name
     */
    bpc_hashtable filesHT;
} bpc_attrib_dir;

bpc_attrib_xattr *bpc_attrib_xattrGet(bpc_attrib_file *file, void *key, int keyLen, int allocate_if_missing);
void bpc_attrib_xattrDestroy(bpc_attrib_xattr *xattr);
int bpc_attrib_xattrDelete(bpc_attrib_file *file, void *key, int keyLen);
int bpc_attrib_xattrDeleteAll(bpc_attrib_file *file);
int bpc_attrib_xattrSetValue(bpc_attrib_file *file, void *key, int keyLen, void *value, uint32 valueLen);
int bpc_attrib_xattrCount(bpc_attrib_file *file);
size_t bpc_attrib_xattrList(bpc_attrib_file *file, char *list, size_t listLen, int ignoreRsyncACLs);
void bpc_attrib_fileInit(bpc_attrib_file *file, char *fileName, int xattrNumEntries);
void bpc_attrib_fileDestroy(bpc_attrib_file *file);
bpc_attrib_file *bpc_attrib_fileGet(bpc_attrib_dir *dir, char *fileName, int allocate_if_missing);
void bpc_attrib_fileCopyOpt(bpc_attrib_file *fileDest, bpc_attrib_file *fileSrc, int overwriteEmptyDigest);
void bpc_attrib_fileCopy(bpc_attrib_file *fileDest, bpc_attrib_file *fileSrc);
int bpc_attrib_fileCompare(bpc_attrib_file *file0, bpc_attrib_file *file1);
void bpc_attrib_fileDeleteName(bpc_attrib_dir *dir, char *fileName);
int bpc_attrib_fileCount(bpc_attrib_dir *dir);
char *bpc_attrib_fileType2Text(int type);
void bpc_attrib_dirInit(bpc_attrib_dir *dir, int compressLevel);
void bpc_attrib_dirDestroy(bpc_attrib_dir *dir);
ssize_t bpc_attrib_getEntries(bpc_attrib_dir *dir, char *entries, ssize_t entrySize);
void bpc_attrib_dirRefCount(bpc_attrib_dir *dir, int incr);
void bpc_attrib_attribFilePath(char *path, char *dir, char *attribFileName);
bpc_digest *bpc_attrib_dirDigestGet(bpc_attrib_dir *dir);
uchar *bpc_attrib_buf2file(bpc_attrib_file *file, uchar *buf, uchar *bufEnd, int xattrNumEntries);
uchar *bpc_attrib_buf2fileFull(bpc_attrib_file *file, uchar *buf, uchar *bufEnd);
uchar *bpc_attrib_file2buf(bpc_attrib_file *file, uchar *buf, uchar *bufEnd);
int bpc_attrib_digestRead(bpc_attrib_dir *dir, bpc_digest *digest, char *attribPath);
int bpc_attrib_dirRead(bpc_attrib_dir *dir, char *dirPath, char *attribFileName, int backupNum);
int bpc_attrib_dirWrite(bpc_attrib_dir *dir, char *dirPath, char *attribFileName, bpc_digest *oldDigest);

/*
 * Attrib caching
 */ 

#define BPC_FTYPE_FILE                  (0)
#define BPC_FTYPE_HARDLINK              (1)
#define BPC_FTYPE_SYMLINK               (2)
#define BPC_FTYPE_CHARDEV               (3)
#define BPC_FTYPE_BLOCKDEV              (4)
#define BPC_FTYPE_DIR                   (5)
#define BPC_FTYPE_FIFO                  (6)
#define BPC_FTYPE_SOCKET                (8)
#define BPC_FTYPE_UNKNOWN               (9)
#define BPC_FTYPE_DELETED               (10)
#define BPC_FTYPE_INVALID               (11)

typedef struct {
    int num;
    int compress;
    int version;
} bpc_backup_info;

typedef struct {
    int backupNum;
    int compress;
    int readOnly;
    uint cacheLruCnt;

    /*
     * optional merging of backups to create view for restore
     */
    bpc_backup_info *bkupMergeList;
    int bkupMergeCnt;

    /*
     * Hash table of cached file attributes.
     * Key   is the mangled attrib path (excluding backupTopDir[], and including attrib file name).
     * Value is a bpc_attrib_dir structure.
     *    - Keys of the bpc_attrib_dir hash table are the file names in that directory.
     */
    bpc_hashtable attrHT;

    /*
     * Hash table of cached inode attributes.
     * Key is the inode attribute path (excluding backupTopDir[]).
     * Value is a bpc_attrib_dir structure.
     *    - Keys of the bpc_attrib_dir hash table are the inode numbers converted to ascii hex, lsb first.
     */
    bpc_hashtable inodeHT;

    char shareName[BPC_MAXPATHLEN];
    int shareNameLen;
    char shareNameUM[BPC_MAXPATHLEN];
    char hostName[BPC_MAXPATHLEN];
    char hostDir[BPC_MAXPATHLEN];
    char backupTopDir[BPC_MAXPATHLEN];
    char currentDir[BPC_MAXPATHLEN];
} bpc_attribCache_info;

typedef struct {
    bpc_hashtable_key key;
    int dirty;
    /* 
     * We flag directories whose parents either don't exist or aren't directories.
     * We ignore attributes on bad directories.
     * Initially this flag is zero, meaning we don't know if this directory is ok.
     * After we check, > 0 means parent does exist and is a directory ; < 0 means dir is bad
     */
    int dirOk;
    uint lruCnt;
    bpc_attrib_dir dir;
} bpc_attribCache_dir;

void bpc_attribCache_init(bpc_attribCache_info *ac, char *host, int backupNum, char *shareNameUM, int compress);
void bpc_attribCache_setMergeList(bpc_attribCache_info *ac, bpc_backup_info *bkupList, int bkupCnt);
void bpc_attribCache_destroy(bpc_attribCache_info *ac);
int bpc_attribCache_readOnly(bpc_attribCache_info *ac, int readOnly);
void bpc_attribCache_setCurrentDirectory(bpc_attribCache_info *ac, char *dir);
bpc_attrib_file *bpc_attribCache_getFile(bpc_attribCache_info *ac, char *path, int allocate_if_missing, int dontReadInode);
int bpc_attribCache_setFile(bpc_attribCache_info *ac, char *path, bpc_attrib_file *file, int dontOverwriteInode);
int bpc_attribCache_deleteFile(bpc_attribCache_info *ac, char *path);
bpc_attrib_file *bpc_attribCache_getInode(bpc_attribCache_info *ac, ino_t inode, int allocate_if_missing);
int bpc_attribCache_setInode(bpc_attribCache_info *ac, ino_t inode, bpc_attrib_file *inodeSrc);
int bpc_attribCache_deleteInode(bpc_attribCache_info *ac, ino_t inode);
int bpc_attribCache_getDirEntryCnt(bpc_attribCache_info *ac, char *path);
ssize_t bpc_attribCache_getDirEntries(bpc_attribCache_info *ac, char *path, char *entries, ssize_t entrySize);
void bpc_attribCache_flush(bpc_attribCache_info *ac, int all, char *path);
void bpc_attribCache_getFullMangledPath(bpc_attribCache_info *ac, char *path, char *dirName, int backupNum);

#endif
