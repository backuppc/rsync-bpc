/*
 * Emulate system calls for BackupPC.
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

#include "backuppc/backuppc.h"
#include "ifuncs.h"

#define MAX_FD          (64)
#define MAX_BUF_SZ      (8 << 20)               /* 8MB */

extern int am_generator;
extern int always_checksum;
extern int protocol_version;

static bpc_attribCache_info acNew;
static bpc_attribCache_info acOld;
static int acOldUsed;

static int LogLevel;
static int DoneInit = 0;
static int CompressLevel;

typedef struct _bpc_sysCall_stats {
    ino_t Inode0, InodeCurr;
    int64 ErrorCnt;
    int64 ExistFileCnt, ExistFileSize, ExistFileCompSize;
    int64 NewFileCnt, NewFileSize, NewFileCompSize;
    int64 TotalFileCnt, TotalFileSize;
} bpc_sysCall_stats;

static bpc_sysCall_stats Stats;

static void logMsgCB(UNUSED(int errFlag), char *mesg, size_t mesgLen)
{
    fwrite(mesg, 1, mesgLen, stderr);
    fflush(stderr);
    //rwrite(errFlag ? FERROR : FINFO, mesg, mesgLen, 0);
}

void bpc_sysCall_init(
            char *topDir,               /* backuppc top-level data dir path */
            char *hostName,             /* host name */
            char *shareNameUM,          /* unmangled share name */
            int newBkupNum,             /* new backup number */
            int newCompress,            /* compression level for new backup */
            int prevBkupNum,            /* prior backup number (or -1) */
            int prevCompress,           /* comperssion level for prior backup */
            char *mergeBkupInfo,        /* which backups to merge together on read */
            ino_t inode0,               /* starting inode number for this backup */
            int logLevel                /* logging level */
        )
{
    static char hostDir[BPC_MAXPATHLEN];
    extern int BPC_HardLinkMax;
    extern int BPC_PoolV3Enabled;

    bpc_logMsgCBSet(logMsgCB);
    bpc_lib_conf_init(topDir, BPC_HardLinkMax, BPC_PoolV3Enabled, logLevel);
    bpc_attribCache_init(&acNew, hostName, newBkupNum, shareNameUM, newCompress);
    CompressLevel = newCompress;
    if ( prevBkupNum >= 0 ) {
        bpc_attribCache_init(&acOld, hostName, prevBkupNum, shareNameUM, prevCompress);
        acOldUsed = 1;
    } else {
        acOldUsed = 0;
    }
    snprintf(hostDir, sizeof(hostDir), "%s/pc/%s", topDir, hostName);
    bpc_poolRefDeltaFileInit(hostDir);
    Stats.InodeCurr = Stats.Inode0 = inode0;
    LogLevel = logLevel;
    if ( mergeBkupInfo && *mergeBkupInfo ) {
        /*
         * Count number of backups to merge: 1 + number of commas.
         */
        int i, bkupCnt = 1;
        char *p = mergeBkupInfo;
        bpc_backup_info *bkupList;

        while ( (p = strchr(p + 1, ',')) ) {
            bkupCnt++;
        }
        p = mergeBkupInfo;
        if ( !(bkupList = calloc(bkupCnt, sizeof(bpc_backup_info))) ) {
            bpc_logErrf("bpc_sysCall_init: can't allocate backup list (%d)\n", bkupCnt);
            return;
        }
        for ( i = 0 ; i < bkupCnt ; i++ ) {
            if ( sscanf(p, "%d/%d/%d", &bkupList[i].num, &bkupList[i].compress, &bkupList[i].version) != 3 ) {
                bpc_logErrf("bpc_sysCall_init: can't parse bkup info string %s\n", p);
                return;
            }
            if ( !(p = strchr(p, ',')) ) break;
            p++;
        }
        bpc_attribCache_setMergeList(&acNew, bkupList, bkupCnt);
    }
    DoneInit = 1;
}

void bpc_am_generator(int generator, int pid)
{
    if ( generator ) {
        Stats.InodeCurr = 2 * (Stats.InodeCurr / 2) + 0;
        bpc_logMsgf("xferPids %d,%d\n", getpid(), pid);
    } else {
        Stats.InodeCurr = 2 * (Stats.InodeCurr / 2) + 1;
        bpc_attribCache_readOnly(&acNew, 1);
        if ( acOldUsed ) bpc_attribCache_readOnly(&acOld, 1);
    }
    bpc_lib_setTmpFileUnique(generator);
}

int bpc_sysCall_cleanup(void)
{
    fflush(stdout);
    fflush(stderr);
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_sysCall_cleanup: doneInit = %d\n", DoneInit);
    if ( !DoneInit ) return 0;
    if ( am_generator ) {
        bpc_attribCache_flush(&acNew, 1, NULL);
        if ( acOldUsed ) bpc_attribCache_flush(&acOld, 1, NULL);
    }
    if ( LogLevel >= 6 ) bpc_poolRefDeltaPrint();
    Stats.ErrorCnt += bpc_poolRefDeltaFileFlush();
    fprintf(stderr, "%s: %llu errors, %llu filesExist, %llu sizeExist, %llu sizeExistComp, %llu filesTotal, %llu sizeTotal, %llu filesNew, %llu sizeNew, %llu sizeNewComp, %llu inode\n",
            am_generator ? "DoneGen" : "Done",
            (unsigned long long)Stats.ErrorCnt,
            (unsigned long long)Stats.ExistFileCnt,
            (unsigned long long)Stats.ExistFileSize,
            (unsigned long long)Stats.ExistFileCompSize,
            (unsigned long long)Stats.TotalFileCnt,
            (unsigned long long)Stats.TotalFileSize,
            (unsigned long long)Stats.NewFileCnt,
            (unsigned long long)Stats.NewFileSize,
            (unsigned long long)Stats.NewFileCompSize,
            (unsigned long long)Stats.InodeCurr);
    return Stats.ErrorCnt;
}

void bpc_progress_fileDone(void)
{
    static int fileCnt = 0, fileCntNext = 1;

    fileCnt++;
    if ( fileCnt < fileCntNext ) return;
    fileCntNext = fileCnt + 20;
    fprintf(stderr, "__bpc_progress_fileCnt__ %d\n", fileCnt);
}

void bpc_sysCall_statusFileSize(unsigned long fileSize)
{
    Stats.TotalFileCnt++;
    Stats.TotalFileSize += fileSize;
    bpc_progress_fileDone();
}

void bpc_sysCall_setInode0Debug(int inode0, char *hostName, char *shareNameUM, int prevBkupNum, int prevCompress)
{
    Stats.Inode0 = inode0;
    if ( prevBkupNum >= 0 ) {
        bpc_attribCache_init(&acOld, hostName, prevBkupNum, shareNameUM, prevCompress);
        acOldUsed = 1;
    }
}

/*
 * File handling
 */
typedef struct {
    int used;
    int fdNum;
    int flags;
    int dirty;
    int mode;
    int fdUnusedNext;
    off_t posn;
    off_t fileSize;
    int tmpFd;
    char *fileName;
    char *tmpFileName;
    char *buffer;
    size_t bufferSize;
    bpc_digest digest;
} FdInfo;

static FdInfo Fd[MAX_FD];

/*
 * We keep a simple integer index free list.  This is the head of the free list.
 * Fd[i].fdUnusedNext points to the next entry on the free list.
 */
static int FdUnused = -1;

/*
 * Find a spare file descriptor.  The integer file descriptors we return
 * here have no relation to real file descriptors.  They are simply handles
 * that allow us to index into the $io->{fileDesc} array.  So long as the
 * caller uses the returned file descriptor only to call these functions
 * (ie: not to directly make IO system calls) then we are ok.
 */
static int bpc_fileDescriptorNew(void)
{
    int i;

    if ( FdUnused < 0 ) {
        /*
         * initialize the free list
         */
        FdUnused = 3;
        for ( i = FdUnused ; i < MAX_FD ; i++ ) {
            Fd[i].used  = 0;
            Fd[i].fdNum = i;
            Fd[i].tmpFd = -1;
            Fd[i].fdUnusedNext = i + 1;
        }
        Fd[MAX_FD-1].fdUnusedNext = -1;
    }
    i = FdUnused;
    if ( i >= 0 ) {
        FdUnused = Fd[i].fdUnusedNext;
        return i;
    } else {
        bpc_logErrf("bpc_fileDescriptorNew: out of file descriptors\n");
        Stats.ErrorCnt++;
        return -1;
    }
}

static void bpc_fileDescFree(FdInfo *fd)
{
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_fileDescFree: fdNum = %d, tmpFd = %d, tmpFileName = %s\n", fd->fdNum, fd->tmpFd, fd->tmpFileName ? fd->tmpFileName : "NULL");

    if ( fd->tmpFd >= 0 ) {
        close(fd->tmpFd);
        fd->tmpFd = -1;
    }
    if ( fd->fileName )    free(fd->fileName);
    if ( fd->buffer )      free(fd->buffer);
    if ( fd->tmpFileName ) {
        unlink(fd->tmpFileName);
        free(fd->tmpFileName);
    }
    fd->used         = 0;
    fd->fdUnusedNext = FdUnused;
    fd->fileName     = NULL;
    fd->buffer       = NULL;
    fd->tmpFileName  = NULL;
    FdUnused = fd->fdNum;
}

static int TmpFileCnt = 0;

static int bpc_fileWriteBuffer(int fdNum, char *buffer, size_t nBytes)
{
    while ( nBytes > 0 ) {
        ssize_t nWrite = write(fdNum, buffer, nBytes);
        if ( nWrite < 0 ) {
            if ( errno == EINTR ) continue;
            return -1;
        }
        buffer += nWrite;
        nBytes -= nWrite;
    }
    return 0;
}

/*
 * Create a temporary output file and write the existing data buffer there
 */
static int bpc_fileSwitchToDisk(bpc_attribCache_info *ac, FdInfo *fd)
{
    char tmpFileName[BPC_MAXPATHLEN];

    snprintf(tmpFileName, BPC_MAXPATHLEN, "%s/rsyncTmp.%d.%d.%d", ac->backupTopDir, getpid(), am_generator, TmpFileCnt++);
    fd->tmpFileName = malloc(strlen(tmpFileName) + 1);
    if ( !fd->tmpFileName ) {
        bpc_logErrf("bpc_fileSwitchToDisk: can't allocated %lu bytes for temp file name\n", (unsigned long)strlen(tmpFileName) + 1);
        Stats.ErrorCnt++;
        return -1;
    }
    strcpy(fd->tmpFileName, tmpFileName); 
    if ( (fd->tmpFd = open(fd->tmpFileName, O_RDWR | O_CREAT | O_TRUNC, 0600)) < 0 ) {
        bpc_logErrf("bpc_fileSwitchToDisk: can't open/create %s for writing\n", fd->tmpFileName);
        Stats.ErrorCnt++;
        return -1;
    }
    if ( fd->fileSize > 0 && bpc_fileWriteBuffer(fd->tmpFd, fd->buffer, fd->fileSize) ) return -1;
    if ( lseek(fd->tmpFd, fd->posn, SEEK_SET) != fd->posn ) {
        bpc_logErrf("bpc_fileSwitchToDisk: unable to seek %s to %lu\n", fd->tmpFileName, (unsigned long)fd->posn);
        Stats.ErrorCnt++;
        return -1;
    }
    return 0;
}

/*
 * Open a file and cache the file handle and information.  Returns a pointer
 * to an FdInfo structure, or NULL on error.
 *
 * The file is either stored in memory (fh->buffer) or a regular
 * uncompressed unbuffered read-write file with handle fh->tmpFd.
 *
 * The current seek position is fh->posn.
 *
 * If you call fileClose() first, then fileOpen() with $write <= 0, you are
 * guaranteed to get just the read-only BackupPC::FileZIO handle fh->fhRead
 * or the in-memory fh->buffer.
 *
 * The following flags determine behavior:
 *      O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND
 */
static FdInfo *bpc_fileOpen(bpc_attribCache_info *ac, char *fileName, int flags)
{
    bpc_attrib_file *file;
    int fdNum;
    FdInfo *fd;

    file = bpc_attribCache_getFile(&acNew, fileName, 0, 0);
    if ( !file && !(flags & O_CREAT) ) return NULL;
 
    if ( (fdNum = bpc_fileDescriptorNew()) < 0 ) return NULL;
    
    fd = &Fd[fdNum];

    fd->used       = 1;
    fd->posn       = 0;
    fd->fdNum      = fdNum;
    fd->flags      = flags;
    fd->dirty      = 0;
    fd->fileName   = malloc(strlen(fileName) + 1);
    fd->bufferSize = MAX_BUF_SZ;
    fd->buffer     = calloc(fd->bufferSize, sizeof(fd->buffer[0]));
    fd->fileSize   = 0;
    if ( !fd->fileName || !fd->buffer ) {
        bpc_fileDescFree(fd);
        return NULL;
    }
    strcpy(fd->fileName, fileName);

    if ( file && file->size > 0 && !(flags & O_TRUNC) ) {
        char fullPath[BPC_MAXPATHLEN];
        bpc_fileZIO_fd fdz;

        /*
         * need to read existing file
         */
        if ( file->digest.len > 0 ) {
            /*
             * all non-empty V4+ files have digests, so use the digest to look in the pool
             */
            bpc_digest_md52path(fullPath, file->compress, &file->digest);
            if ( bpc_fileZIO_open(&fdz, fullPath, 0, file->compress) ) {
                bpc_logErrf("bpc_fileOpen: can't open pool file %s (from %s, %d, %d)\n", fullPath, fd->fileName, file->compress, file->digest.len);
                Stats.ErrorCnt++;
                bpc_fileDescFree(fd);
                return NULL;
            }
        } else {
            /*
             * must be a V3 file - look in the backup directory
             */
            bpc_attribCache_getFullMangledPath(&acNew, fullPath, (char*)fileName, file->backupNum);
            if ( bpc_fileZIO_open(&fdz, fullPath, 0, file->compress) ) {
                bpc_logErrf("bpc_fileOpen: can't open V3 file %s (from %s, %d, %d)\n", fullPath, fd->fileName, file->compress, file->digest.len);
                Stats.ErrorCnt++;
                bpc_fileDescFree(fd);
                return NULL;
            }
        }
        fd->fileSize = bpc_fileZIO_read(&fdz, (uchar*)fd->buffer, fd->bufferSize);
        if ( fd->fileSize == (off_t)fd->bufferSize ) {
            off_t nRead;
            /*
             * buffer is full - write to flat disk and then copy the rest of the file
             */
            fd->posn = fd->bufferSize;
            if ( bpc_fileSwitchToDisk(ac, fd) ) {
                bpc_fileDescFree(fd);
                return NULL;
            }
            while ( (nRead = bpc_fileZIO_read(&fdz, (uchar*)fd->buffer, fd->bufferSize)) > 0 ) {
                if ( bpc_fileWriteBuffer(fd->tmpFd, fd->buffer, nRead) ) {
                    bpc_fileDescFree(fd);
                    return NULL;
                }
            }
        }
        bpc_fileZIO_close(&fdz);
    }
    if ( fd->tmpFd >= 0 ) {
        if ( !(flags & O_APPEND) && lseek(fd->tmpFd, 0, SEEK_SET) != 0 ) {
            bpc_logErrf("bpc_fileOpen: can't seek to start of file %s\n", fd->tmpFileName);
            Stats.ErrorCnt++;
            bpc_fileDescFree(fd);
            return NULL;
        }
    } else {
        if ( (flags & O_APPEND) ) fd->posn = fd->fileSize;
    }
    return fd;
}

static int bpc_fileWrite(bpc_attribCache_info *ac, FdInfo *fd, char *buf, size_t bufLen)
{
    if ( fd->tmpFd < 0 ) {
        if ( (size_t)fd->posn + bufLen <= fd->bufferSize ) {
            if ( fd->posn + (off_t)bufLen > fd->fileSize || memcmp(fd->buffer + fd->posn, buf, bufLen) ) {
                fd->dirty = 1;
                memcpy(fd->buffer + fd->posn, buf, bufLen);
            }
            fd->posn += bufLen;
            if ( fd->fileSize < fd->posn ) fd->fileSize = fd->posn;
            return 0;
        }
        /*
         * We would overflow the buffer, so write to a file instead
         */
        if ( bpc_fileSwitchToDisk(ac, fd) ) return -1;
    }
    fd->dirty = 1;
    return bpc_fileWriteBuffer(fd->tmpFd, buf, bufLen);
}

static int bpc_fileClose(bpc_attribCache_info *ac, FdInfo *fd, int newType, int newMode, char *fileNameLog)
{
    bpc_attrib_file *file;
    off_t fileSize = 0;
    static bpc_poolWrite_info pwInfo;
    bpc_digest digest;
    int match;
    off_t poolFileSize;
    int errorCnt;

    file = bpc_attribCache_getFile(&acNew, fd->fileName, 0, 0);
    if ( file && newType < 0 ) newType = file->type;
    if ( newType < 0 ) newType = BPC_FTYPE_FILE;

    if ( file && file->size != fd->fileSize && ((fd->flags & O_WRONLY) || (fd->flags & O_RDWR)) ) {
        fd->dirty = 1;
    }
    if ( !fd->dirty ) {
        if ( (fd->flags & O_WRONLY) || (fd->flags & O_RDWR) ) {
            fprintf(stderr, "IOdone: same %s\n", fd->fileName);
        }
        bpc_fileDescFree(fd);
        return 0;
    }

    if ( fd->tmpFd < 0 ) {
        fileSize = fd->fileSize;
        bpc_poolWrite_open(&pwInfo, ac->compress, NULL);
        bpc_poolWrite_write(&pwInfo, (uchar*)fd->buffer, fileSize);
        bpc_poolWrite_close(&pwInfo, &match, &digest, &poolFileSize, &errorCnt);
    } else {
        off_t nRead;

        lseek(fd->tmpFd, 0, SEEK_SET);
        bpc_poolWrite_open(&pwInfo, ac->compress, NULL);
        while ( (nRead = read(fd->tmpFd, fd->buffer, fd->bufferSize)) > 0 ) {
            bpc_poolWrite_write(&pwInfo, (uchar*)fd->buffer, nRead);
            fileSize += nRead;
        }
        bpc_poolWrite_close(&pwInfo, &match, &digest, &poolFileSize, &errorCnt);
    }

    Stats.ErrorCnt += errorCnt;

    if ( match ) {
        Stats.ExistFileCnt++;
        if ( newType == BPC_FTYPE_FILE || newType == BPC_FTYPE_SYMLINK ) {
            Stats.ExistFileSize     += fileSize;
            Stats.ExistFileCompSize += poolFileSize;
        }
    } else {
        Stats.NewFileCnt++;
        if ( newType == BPC_FTYPE_FILE || newType == BPC_FTYPE_SYMLINK ) {
            Stats.NewFileSize     += fileSize;
            Stats.NewFileCompSize += poolFileSize;
        }
    }

    if ( file && file->digest.len == digest.len && !memcmp(file->digest.digest, digest.digest, digest.len)
                    && file->size == fileSize ) {
        /*
         * File is unchanged
         */
        fprintf(stderr, "IOdone: same %s\n", fd->fileName);
        bpc_fileDescFree(fd);
        return 0;
    }

    if ( file && !file->isTemp ) {
        if ( acOldUsed && file->inode < Stats.Inode0 && !bpc_attribCache_getFile(&acOld, fd->fileName, 0, 0) ) {
            if ( file->nlinks > 0 ) {
                /*
                 * Only write the inode if it doesn't exist in old;
                 * in that case increase the pool reference count
                 */
                if ( bpc_attribCache_setFile(&acOld, fd->fileName, file, 1) > 0 ) {
                    bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
                }
            } else {
                bpc_attribCache_setFile(&acOld, fd->fileName, file, 0);
            }
        } else {
            /*
             * The current file is new to this backup and will be replaced below, so reduce
             * the ref count of the existing (old) file.
             */
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, -1);
        }
    } else if ( acOldUsed && (!file || !file->isTemp) && !bpc_attribCache_getFile(&acOld, fd->fileName, 0, 0) ) {
        bpc_attrib_file *oldFile = bpc_attribCache_getFile(&acOld, fd->fileName, 1, 0);
        oldFile->type = BPC_FTYPE_DELETED;
        bpc_attribCache_setFile(&acOld, fd->fileName, oldFile, 0);
    }
    if ( !file ) {
        file = bpc_attribCache_getFile(&acNew, fd->fileName, 1, 0);
        file->inode      = Stats.InodeCurr;
        Stats.InodeCurr += 2;
        file->nlinks     = 0;
        file->mode       = fd->mode;
    }
    file->compress = ac->compress;
    file->digest   = digest;
    if ( newType >= 0 ) file->type = newType;
    if ( newMode >= 0 ) file->mode = newMode;
    if ( file->type == BPC_FTYPE_FILE || file->type == BPC_FTYPE_SYMLINK ) {
        file->size = fileSize;
    } else {
        file->size = 0;
    }
    if ( !file->isTemp ) bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
    bpc_attribCache_setFile(&acNew, fd->fileName, file, 0);
    fprintf(stderr, "IOdone: %s %s\n", match ? "pool" : "new", fileNameLog ? fileNameLog : fd->fileName);
    bpc_fileDescFree(fd);
    return 0;
}

/*
 * Read an entire file into the buffer, up until the buffer is full. Returns the number
 * of bytes read, or -1 on error.
 */
static off_t bpc_fileReadAll(bpc_attribCache_info *ac, char *fileName, char *buffer, size_t bufferSize)
{
    char fullPath[BPC_MAXPATHLEN];
    bpc_attrib_file *file;
    bpc_fileZIO_fd fd;
    off_t nRead;

    if ( !(file = bpc_attribCache_getFile(ac, fileName, 0, 0)) ) return -1;
    if ( file->digest.len > 0 ) {
        /*
         * V4+ pool file
         */
        bpc_digest_md52path(fullPath, file->compress, &file->digest);
    } else {
        /*
         * V3 look in the backup directory
         */
        bpc_attribCache_getFullMangledPath(&acNew, fullPath, (char*)fileName, file->backupNum);
    }
    if ( bpc_fileZIO_open(&fd, fullPath, 0, file->compress) ) {
        bpc_logErrf("bpc_fileReadAll: can't open %s (from %s)\n", fullPath, fileName);
        Stats.ErrorCnt++;
        return -1;
    }
    nRead = bpc_fileZIO_read(&fd, (uchar*)buffer, bufferSize);
    bpc_fileZIO_close(&fd);
    return nRead;
}

/*
 * Directory handling
 */
typedef struct {
    struct dirent dirent;
    char *entries;
    ssize_t entrySize;
    ssize_t entryIdx;
} my_DIR;

char *bpc_mktemp(char *template)
{
    char *p = template + strlen(template);
    int i, xCnt = 0;

    while ( p > template && p[-1] == 'X' ) {
        p--;
        xCnt++;
    }
    if ( xCnt == 0 ) return NULL;
    for ( i = 0 ; i < (1 << (4 * xCnt)) ; i++ ) {
        sprintf(p, "%0*x", xCnt, i);
        if ( bpc_attribCache_getFile(&acNew, template, 0, 0)
                || (acOldUsed && bpc_attribCache_getFile(&acOld, template, 0, 0)) ) {
            continue;
        }
        if ( LogLevel >= 7 ) bpc_logMsgf("bpc_mktemp: returning %s\n", template);
        return template;
    }
    if ( LogLevel >= 7 ) bpc_logMsgf("bpc_mktemp: returning NULL\n");
    return NULL;
}

int bpc_mkstemp(char *template, char *origFileName)
{
    char *p = template + strlen(template);
    bpc_attrib_file *file, *fileOrig = NULL;
    int i, xCnt = 0;
    FdInfo *fd;

    while ( p > template && p[-1] == 'X' ) {
        p--;
        xCnt++;
    }
    if ( xCnt == 0 ) return -1;
    for ( i = 0 ; i < (1 << (4 * xCnt)) ; i++ ) {
        sprintf(p, "%0*x", xCnt, i);
        if ( bpc_attribCache_getFile(&acNew, template, 0, 0)
                || (acOldUsed && bpc_attribCache_getFile(&acOld, template, 0, 0)) ) {
            continue;
        }
        file = bpc_attribCache_getFile(&acNew, template, 1, 0);
        if ( origFileName
                && (fileOrig = bpc_attribCache_getFile(&acNew, origFileName, 0, 0))
                && fileOrig->type == BPC_FTYPE_FILE ) {
            /*
             * We have been told that this temp file is an update of origFileName.
             * If it exists, we copy all the attributes, including the digest,
             * which is a cheap way to make the temp file look just like
             * the orig file.
             */
            if ( LogLevel >= 4 ) bpc_logMsgf("bpc_mkstemp: copying attribs from %s to %s\n", origFileName, template);
            bpc_attrib_fileCopy(file, fileOrig);
            file->nlinks = 0;
        } else {
            /*
             * No orig file, so create new attributes
             */
            file->type       = BPC_FTYPE_FILE;
            file->mode       = 0600;
            file->compress   = CompressLevel;
            file->inode      = Stats.InodeCurr;
            Stats.InodeCurr += 2;
        }
        file->isTemp = 1;
        bpc_attribCache_setFile(&acNew, template, file, 0);
        if ( !(fd = bpc_fileOpen(&acNew, template, O_RDWR | O_CREAT)) ) return -1;
        if ( LogLevel >= 4 ) bpc_logMsgf("bpc_mkstemp: returning %s, fd = %d\n",
                                template, fd->fdNum);
        return fd->fdNum;
    }
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_mkstemp: returning -1\n");
    return -1;
}

/*
 * Confirm that fileName exists, has the indicated size and MD5 file_sum.  If so, mimic
 * mkstemp above by creating a temporary file copy, but don't open it.
 *
 * The is used to implement an optimization in receiver.c: if we are receiving file deltas,
 * we check if the deltas show the file is identical.  That avoids opening the file
 * and copying it to the temp file (which involves a lot of processing given the
 * compression overhead, and disk IO for large files).
 */
int bpc_sysCall_checkFileMatch(char *fileName, char *tmpName, struct file_struct *rsyncFile,
                               char *file_sum, off_t fileSize)
{
    bpc_attrib_file *fileOrig, *file;
    char poolPath[BPC_MAXPATHLEN];
    STRUCT_STAT st;

    if ( !(fileOrig = bpc_attribCache_getFile(&acNew, fileName, 0, 0)) ) {
        /*
         * Hmmm.  The file doesn't exist, but we got deltas suggesting the file is
         * unchanged.  So that means the generator found a matching pool file.
         * Let's try the same thing.
         */
        if ( bpc_sysCall_poolFileCheck(fileName, rsyncFile)
                || !(fileOrig = bpc_attribCache_getFile(&acNew, fileName, 0, 0)) ) { 
            bpc_logErrf("bpc_sysCall_checkFileMatch(%s): file doesn't exist\n", fileName);
            return -1;
        }
    }
    if ( fileOrig->size != fileSize || fileOrig->digest.len < MD5_DIGEST_LEN || memcmp(file_sum, fileOrig->digest.digest, MD5_DIGEST_LEN) ) {
        if ( LogLevel >= 4 ) bpc_logMsgf("bpc_sysCall_checkFileMatch(%s): size/digest don't match (%lu/%lu, %d, 0x%02x%02x.../0x%02x%02x...\n",
                                          fileName, (unsigned long)fileOrig->size, (unsigned long)fileSize,
                                          fileOrig->digest.len,
                                          fileOrig->digest.digest[0], fileOrig->digest.digest[1],
                                          ((unsigned)file_sum[0]) & 0xff, ((unsigned)file_sum[1]) & 0xff);
        return -1;
    }

    /*
     * make sure the pool file exists
     */
    bpc_digest_md52path(poolPath, CompressLevel, &fileOrig->digest);
    if ( fileSize != 0 && stat(poolPath, &st) ) {
        bpc_logErrf("bpc_sysCall_checkFileMatch(%s): got good match, but pool file %s doesn't exist - rewriting\n",
                                    fileName, poolPath);
        return -1;
    }
    if ( st.st_mode & S_IXOTH ) {
        /*
         * pool file is marked for deletion - safely unmark it since we going to use it
         */
        if ( bpc_poolWrite_unmarkPendingDelete(poolPath) ) {
            bpc_logErrf("bpc_sysCall_checkFileMatch(%s): couldn't unmark pool file %s - rewriting\n",
                                        fileName, poolPath);
            return -1;
        }
    }

    /*
     * Now mimic bpc_mkstemp() above
     */
    if ( !get_tmpname(tmpName, fileName) || !bpc_mktemp(tmpName) ) {
        bpc_logErrf("bpc_sysCall_checkFileMatch(%s): tmp name failed\n", fileName);
        return -1;
    }
    file = bpc_attribCache_getFile(&acNew, tmpName, 1, 0);
    bpc_attrib_fileCopy(file, fileOrig);
    file->nlinks = 0;
    file->isTemp = 1;
    bpc_attribCache_setFile(&acNew, tmpName, file, 0);
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_sysCall_checkFileMatch(%s): good match, made copy in %s\n", fileName, tmpName);
    fprintf(stderr, "IOdone: same %s\n", tmpName);
    return 0;
}


/*
 * This is called by the generator-side to see if there is a matching pool
 * file that can be used for the block checksums.  This needs to match
 * mks_temp above to make sure the same basis file is used by each side.
 *
 * If there is a match, we create a temp file entry, which will be replaced
 * when the receiver does the rename.
 */
int bpc_sysCall_poolFileCheck(char *fileName, struct file_struct *rsyncFile)
{
    bpc_digest digest;
    char poolPath[BPC_MAXPATHLEN];
    STRUCT_STAT st;
    unsigned int ext;
    int foundPoolFile = 0;

    if ( protocol_version < 30 || !always_checksum ) return -1;

    digest.len = MD5_DIGEST_LEN;
    memcpy(digest.digest, F_SUM(rsyncFile), MD5_DIGEST_LEN);

    /*
     * find the first non-empty pool file in the chain
     */
    if ( F_LENGTH(rsyncFile) > 0 ) {
        for ( ext = 0 ; !foundPoolFile ; ext++ ) {
            bpc_digest_append_ext(&digest, ext);
            bpc_digest_md52path(poolPath, CompressLevel, &digest);
            if ( stat(poolPath, &st) ) break;
            if ( st.st_size == 0 ) continue;
            if ( st.st_mode & S_IXOTH ) {
                /*
                 * pool file is marked for deletion - safely unmark it since we going to use it
                 */
                if ( bpc_poolWrite_unmarkPendingDelete(poolPath) ) {
                    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_sysCall_poolFileCheck(%s): couldn't unmark potential match %s\n", fileName, poolPath);
                    continue;
                }
            }
            foundPoolFile = 1;
        }
    } else {
        foundPoolFile = 1;
    }
    if ( foundPoolFile ) {
        bpc_attrib_file *file = bpc_attribCache_getFile(&acNew, fileName, 1, 0);

        if ( LogLevel >= 4 ) bpc_logMsgf("bpc_sysCall_poolFileCheck(%s): potential match %s (len = %lu)\n", fileName, poolPath, (unsigned long)F_LENGTH(rsyncFile));
        file->type        = BPC_FTYPE_FILE;
        file->size        = F_LENGTH(rsyncFile);
        file->mode        = 0600;
        file->inode       = Stats.InodeCurr;
        file->compress   = CompressLevel;
        Stats.InodeCurr  += 2;
        file->digest      = digest;
        file->isTemp      = 1;
        return 0;
    } else {
        if ( LogLevel >= 4 ) bpc_logMsgf("bpc_sysCall_poolFileCheck(%s): no pool file at %s\n", fileName, poolPath);
        return -1;
    }
}

/*
 * Print file transfer status for retry and fail
 */
void bpc_sysCall_printfileStatus(char *fileName, char *status)
{
    fprintf(stderr, "IOdone: %s %s\n", status, fileName);
}

/*
 * TODO: do target if symlink?
 */
int bpc_lchmod(const char *fileName, mode_t mode)
{
    bpc_attrib_file *file;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lchmod(%s, 0%o)\n", fileName, mode);

    if ( !(file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) ) {
        errno = ENOENT;
        return -1;
    }
    if ( file->mode == mode ) return 0;

    if ( acOldUsed && !file->isTemp && file->inode < Stats.Inode0 && !bpc_attribCache_getFile(&acOld, (char*)fileName, 0, 0) ) {
        if ( bpc_attribCache_setFile(&acOld, (char*)fileName, file, 1) ) {
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        }
    }
    file->mode = mode;
    bpc_attribCache_setFile(&acNew, (char*)fileName, file, 0);
    return 0;
}

int bpc_fchmod(int filedes, mode_t mode)
{
    if ( filedes < 0 || filedes >= MAX_FD || !Fd[filedes].used ) {
        errno = EBADF;
        return -1;
    }
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_fchmod(%d (%s), 0%o)\n",
                                    filedes, Fd[filedes].fileName, mode);
    return bpc_lchmod(Fd[filedes].fileName, mode);
}

int bpc_unlink(const char *fileName)
{
    bpc_attrib_file *file;
    int deleteInode = 0;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_unlink(%s)\n", fileName);

    if ( !(file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) ) {
        errno = ENOENT;
        return -1;
    }
    if ( file->type == BPC_FTYPE_DIR ) {
        errno = EISDIR;
        return -1;
    }

    if ( file->nlinks > 0 ) {
        if ( acOldUsed && !file->isTemp && !bpc_attribCache_getInode(&acOld, file->inode, 0) ) {
            /*
             * copy the inode to old
             */
            if ( LogLevel >= 6 ) bpc_logMsgf("bpc_unlink: setting inode in old (inode = %lu, nlinks = %lu)\n",
                                             (unsigned long)file->inode, (unsigned long)file->nlinks);
            bpc_attribCache_setInode(&acOld, file->inode, file);
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        }
        /*
         * If this file is older than this backup, then move it to old
         * (don't update the inode, since we know it exists after we just
         * copied it).
         */
        if ( file && file->inode < Stats.Inode0 && acOldUsed && !file->isTemp && !bpc_attribCache_getFile(&acOld, (char*)fileName, 0, 0) ) {
            if ( LogLevel >= 6 ) bpc_logMsgf("bpc_unlink: setting %s in old (inode = %lu, nlinks = %lu)\n",
                                              fileName, (unsigned long)file->inode, (unsigned long)file->nlinks);
            bpc_attribCache_setFile(&acOld, (char*)fileName, file, 1);
        }

        /*
         * Now reduce the number of links and update the inode
         * ref count is handled above
         */
        file->nlinks--;
        if ( file->nlinks <= 0 ) {
            deleteInode = 1;
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, -1);
        } else {
            if ( LogLevel >= 6 ) bpc_logMsgf("bpc_unlink: updating inode in new (inode = %lu, nlinks = %lu)\n", (unsigned long)file->inode, (unsigned long)file->nlinks);
            bpc_attribCache_setInode(&acNew, file->inode, file);
        }
    } else {
        /*
         * If this file is older than this backup, then move it
         * to old.  Otherwise just remove it.
         */
        if ( !file->isTemp && file->inode < Stats.Inode0 && acOldUsed ) {
            bpc_attrib_file *fileOld = bpc_attribCache_getFile(&acOld, (char*)fileName, 0, 0);

            if ( !fileOld ) {
                if ( LogLevel >= 6 ) bpc_logMsgf("bpc_unlink: setting %s in old (inode = %lu, nlinks = %lu)\n",
                                                  fileName, (unsigned long)file->inode, (unsigned long)file->nlinks);
                bpc_attribCache_setFile(&acOld, (char*)fileName, file, 0);
            }
        } else if ( !file->isTemp ) {
            if ( file->digest.len > 0 ) {
                bpc_poolRefDeltaUpdate(file->compress, &file->digest, -1);
            }
        }
    }
    if ( deleteInode ) {
        if ( LogLevel >= 6 ) bpc_logMsgf("bpc_unlink: deleting inode in new (inode = %lu)\n",
                                            (unsigned long)file->inode);
        bpc_attribCache_deleteInode(&acNew, file->inode);
    }
    bpc_attribCache_deleteFile(&acNew, (char*)fileName);
    return 0;
}

int bpc_lstat(const char *fileName, struct stat *buf)
{
    bpc_attrib_file *file;
    dev_t rdev = 0;

    /*
     * must be in order of BPC_FTYPE_* definitions
     */
    static uint fmode[] = {
        S_IFREG,                /* BPC_FTYPE_FILE */
        S_IFREG,                /* BPC_FTYPE_HARDLINK */
        S_IFLNK,                /* BPC_FTYPE_SYMLINK */
        S_IFCHR,                /* BPC_FTYPE_CHARDEV */
        S_IFBLK,                /* BPC_FTYPE_BLOCKDEV */
        S_IFDIR,                /* BPC_FTYPE_DIR */
        S_IFIFO,                /* BPC_FTYPE_FIFO */
        S_IFSOCK,               /* BPC_FTYPE_SOCKET */
        S_IFREG,                /* BPC_FTYPE_UNKNOWN */
        S_IFREG,                /* BPC_FTYPE_DELETED */
    };

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lstat(%s)\n", fileName);

    if ( !(file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) ) {
        errno = ENOENT;
        return -1;
    }
    if ( file->type == BPC_FTYPE_DELETED || file->type == BPC_FTYPE_UNKNOWN || file->type >= BPC_FTYPE_INVALID ) {
        errno = ENOENT;
        return -1;
    }
    if ( file->type == BPC_FTYPE_CHARDEV || file->type == BPC_FTYPE_BLOCKDEV ) {
        char data[BPC_MAXPATHLEN];
        int minor = 0, major = 0;
        int nRead = bpc_fileReadAll(&acNew, (char*)fileName, data, sizeof(data) - 1);

        rdev = 1;
        if ( nRead >= 0 ) {
            data[nRead] = '\0';
            if ( sscanf(data, "%d,%d", &major, &minor) == 2 ) {
                rdev = MAKEDEV(major, minor);
            }
        }
    }
    buf->st_dev = 1;
    buf->st_ino = file->inode;
    buf->st_mode = file->mode;
    buf->st_nlink = file->nlinks;
    buf->st_uid = file->uid;
    buf->st_gid = file->gid;
    buf->st_rdev = rdev;
    buf->st_atime = file->mtime;
    buf->st_mtime = file->mtime;
    buf->st_ctime = file->mtime;
    buf->st_size  = file->size;
    buf->st_blocks = (file->size + 1023) / 1024;
    buf->st_blksize = 1024;

    if ( file->type < sizeof(fmode) / sizeof(fmode[0]) ) {
        buf->st_mode |= fmode[file->type];
    }

    return 0;
}

int bpc_fstat(int filedes, struct stat *buf)
{
    int ret;

    if ( filedes < 0 || filedes >= MAX_FD || !Fd[filedes].used ) {
        errno = EBADF;
        return -1;
    }
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_fstat(%d (%s))\n", filedes, Fd[filedes].fileName);
    ret = bpc_lstat(Fd[filedes].fileName, buf);

    /*
     * TODO: needed??  Based on the current write file update the size...
     */
    return ret;
}

int bpc_stat(const char *fileName, struct stat *buf)
{
    bpc_attrib_file *file;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_stat(%s)\n", fileName);
    if ( (file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) && file->type == BPC_FTYPE_SYMLINK ) {
        char targetName[BPC_MAXPATHLEN];
        int nRead = bpc_fileReadAll(&acNew, (char*)fileName, targetName, sizeof(targetName) - 1);
        /*
         * TODO: combine fileName and targetName if targetName is relative
         * TODO: what happens if $targetName is a symlink?
         */
        if ( nRead <= 0 ) {
            errno = ENOENT;
            return -1;
        }
        targetName[nRead] = '\0';
        return bpc_lstat(targetName, buf);
    } else {
        return bpc_lstat(fileName, buf);
    }
}

int bpc_file_checksum(char *fileName, char *sum, int checksum_len)
{
    bpc_attrib_file *file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0); 
    char poolPath[BPC_MAXPATHLEN];
    STRUCT_STAT st;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_file_checksum(%s)\n", fileName);
    if ( !file || file->digest.len < checksum_len ) return -1;
    /*
     * check the pool file actually exists before returning the digest.
     */
    bpc_digest_md52path(poolPath, file->compress, &file->digest);
    if ( stat(poolPath, &st) ) return -1;
    if ( st.st_mode & S_IXOTH ) {
        /*
         * pool file is marked for deletion - safely unmark it since we are using it
         */
        if ( bpc_poolWrite_unmarkPendingDelete(poolPath) ) {
            bpc_logErrf("bpc_file_checksum(%s): couldn't unmark pool file %s - returning no match\n",
                                        fileName, poolPath);
            return -1;
        }
    }
    memcpy(sum, file->digest.digest, checksum_len);
    return 0;
}

/*
 * the link contents (ie: target) are kept in the original client
 * charset (ie: not converted to utf8).
 */
int bpc_symlink(const char *fileName, const char *symName)
{
    bpc_attrib_file *file;
    FdInfo *fd;
    int ret = 0;
    char logText[2 * BPC_MAXPATHLEN + 32];

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_symlink(%s, %s)\n", fileName, symName);
    /*
     * it's an error if symname exists
     */
    if ( (file = bpc_attribCache_getFile(&acNew, (char*)symName, 0, 0)) ) {
        errno = EEXIST;
        return -1;
    }

    /*
     * add delete attribute to old if nothing is in old
     */
    if ( acOldUsed && !bpc_attribCache_getFile(&acOld, (char*)symName, 0, 0) ) {
        file = bpc_attribCache_getFile(&acOld, (char*)symName, 1, 0);
        file->type = BPC_FTYPE_DELETED;
        bpc_attribCache_setFile(&acOld, (char*)symName, file, 0);
    }

    if ( !(fd = bpc_fileOpen(&acNew, (char*)symName, O_WRONLY | O_CREAT | O_TRUNC)) ) {
        bpc_logErrf("bpc_symlink: open/create of %s failed\n", symName);
        Stats.ErrorCnt++;
        return -1;
    }
    if ( bpc_fileWrite(&acNew, fd, (char*)fileName, strlen(fileName)) ) {
        bpc_logErrf("bpc_symlink: write failed\n");
        ret = -1;
        Stats.ErrorCnt++;
    }
    snprintf(logText, sizeof(logText), "%s -> %s", symName, fileName);
    if ( bpc_fileClose(&acNew, fd, BPC_FTYPE_SYMLINK, 0777, logText) ) {
        bpc_logErrf("bpc_symlink: close failed\n");
        ret = -1;
        Stats.ErrorCnt++;
    }
    return ret;
}

int bpc_link(const char *targetName, const char *linkName)
{
    bpc_attrib_file *file;
    char poolPath[BPC_MAXPATHLEN];
    STRUCT_STAT st;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_link(%s, %s)\n", targetName, linkName);

    if ( bpc_attribCache_getFile(&acNew, (char*)linkName, 0, 0) ) {
        errno = EEXIST;
        return -1;
    }

    /*
     * check if the target exists.  hardlinks to directories are not supported.
     */
    if ( !(file = bpc_attribCache_getFile(&acNew, (char*)targetName, 0, 0))
                    || file->type == BPC_FTYPE_DIR ) {
        errno = ENOENT;
        return -1;
    }

    /*
     * reference counts are unchanged in each of these cases (first link and additional link)
     */
    if ( file->nlinks == 0 ) {
        /*
         * first save the original target file (since it a regular file with no links)
         */
        if ( acOldUsed && !bpc_attribCache_getFile(&acOld, (char*)targetName, 0, 0) ) {
            bpc_attribCache_setFile(&acOld, (char*)targetName, file, 0);
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        }
        /*
         * promote the target to a hardlink; both files are identical
         */
        file->nlinks = 2;
        bpc_attribCache_setFile(&acNew, (char*)targetName, file, 0);
        bpc_attribCache_setFile(&acNew, (char*)linkName, file, 0);
    } else {
        /*
         * save the inode away since the link count is going to increase
         */
        if ( acOldUsed && !bpc_attribCache_getInode(&acOld, file->inode, 0) ) {
            bpc_attribCache_setInode(&acOld, file->inode, file);
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        }
        /*
         * reference count is unchanged since the inode already points at the pool file
         */
        file->nlinks++;
        bpc_attribCache_setFile(&acNew, (char*)linkName, file, 0);
    }

    Stats.ExistFileCnt++;
    Stats.ExistFileSize += file->size;
    bpc_digest_md52path(poolPath, file->compress, &file->digest);
    if ( !stat(poolPath, &st) ) Stats.ExistFileCompSize += st.st_size;

    if ( acOldUsed && !bpc_attribCache_getFile(&acOld, (char*)linkName, 0, 0) ) {
        file = bpc_attribCache_getFile(&acOld, (char*)linkName, 1, 0);
        file->type = BPC_FTYPE_DELETED;
        bpc_attribCache_setFile(&acOld, (char*)linkName, file, 0);
    }
    fprintf(stderr, "IOdone: new %s => %s\n", linkName, targetName);
    return 0;
}

#ifdef HAVE_LUTIMES

int bpc_lutimes(const char *fileName, struct timeval *t)
{
    bpc_attrib_file *file;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lutimes(%s)\n", fileName);
    if ( !(file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) ) {
        errno = ENOENT;
        return -1;
    }
    if ( file->mtime == t[1].tv_sec ) return 0;

    if ( file->inode < Stats.Inode0 && acOldUsed && !file->isTemp && !bpc_attribCache_getFile(&acOld, (char*)fileName, 0, 0) ) {
        if ( bpc_attribCache_setFile(&acOld, (char*)fileName, file, 1) > 0 ) {
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        }
    }
    file->mtime = t[1].tv_sec;
    bpc_attribCache_setFile(&acNew, (char*)fileName, file, 0);
    return 0;
}

#endif

#ifdef HAVE_UTIMES

int bpc_utimes(const char *fileName, struct timeval *t)
{
    bpc_attrib_file *file;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_utimes(%s)\n", fileName);

    if ( (file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) && file->type == BPC_FTYPE_SYMLINK ) {
        char targetName[BPC_MAXPATHLEN];
        int nRead = bpc_fileReadAll(&acNew, (char*)fileName, targetName, sizeof(targetName) - 1);
        /*
         * TODO: combine fileName and targetName if targetName is relative
         * TODO: what happens if $targetName is a symlink?
         */
        if ( nRead <= 0 ) {
            errno = ENOENT;
            return -1;
        }
        targetName[nRead] = '\0';
        return bpc_lutimes(targetName, t);
    } else {
        return bpc_lutimes(fileName, t);
    }
}

#endif

int bpc_lutime(const char *fileName, time_t mtime)
{
    bpc_attrib_file *file;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lutime(%s)\n", fileName);

    if ( !(file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) ) {
        errno = ENOENT;
        return -1;
    }
    if ( file->mtime == mtime ) return 0;

    if ( file->inode < Stats.Inode0 && acOldUsed && !file->isTemp && !bpc_attribCache_getFile(&acOld, (char*)fileName, 0, 0) ) {
        if ( bpc_attribCache_setFile(&acOld, (char*)fileName, file, 1) > 0 ) {
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        }
    }
    file->mtime = mtime;
    bpc_attribCache_setFile(&acNew, (char*)fileName, file, 0);
    return 0;
}

int bpc_utime(const char *fileName, time_t mtime)
{
    bpc_attrib_file *file;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_utime(%s)\n", fileName);

    if ( (file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) && file->type == BPC_FTYPE_SYMLINK ) {
        char targetName[BPC_MAXPATHLEN];
        int nRead = bpc_fileReadAll(&acNew, (char*)fileName, targetName, sizeof(targetName) - 1);
        /*
         * TODO: combine fileName and targetName if targetName is relative
         * TODO: what happens if $targetName is a symlink?
         */
        if ( nRead <= 0 ) {
            errno = ENOENT;
            return -1;
        }
        targetName[nRead] = '\0';
        return bpc_lutime(targetName, mtime);
    } else {
        return bpc_lutime(fileName, mtime);
    }
}

int bpc_lchown(const char *fileName, uid_t uid, gid_t gid)
{
    bpc_attrib_file *file;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lchown(%s, %lu, %lu)\n",
                                    fileName, (unsigned long)uid, (unsigned long)gid);

    if ( !(file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) ) {
        errno = ENOENT;
        return -1;
    }
    if ( file->uid == uid && file->gid == gid ) return 0;

    if ( file->inode < Stats.Inode0 && acOldUsed && !file->isTemp && !bpc_attribCache_getFile(&acOld, (char*)fileName, 0, 0) ) {
        if ( bpc_attribCache_setFile(&acOld, (char*)fileName, file, 1) > 0 ) {
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        }
    }
    file->uid = uid;
    file->gid = gid;
    bpc_attribCache_setFile(&acNew, (char*)fileName, file, 0);
    return 0;
}

int bpc_rename(const char *oldName, const char *newName)
{
    bpc_attrib_file *file, *fileNew;
    int oldIsTemp, fileAttrChanged = 0;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_rename(%s, %s)\n", oldName, newName);

    if ( !(file = bpc_attribCache_getFile(&acNew, (char*)oldName, 0, 0)) ) {
        if ( LogLevel >= 4 ) bpc_logMsgf("bpc_rename: %s doesn't exist\n", oldName);
        errno = ENOENT;
        return -1;
    }
    if ( !am_generator ) {
        /*
         * We don't do renames on the receiver, since it's too hard to keep attribute updates on
         * both the generator and receiver sycnhronized.  Send the attributes to the generator so
         * it can do the rename.
         */
        static xbuf rename_msg = EMPTY_XBUF;
        char *bufP, *bufPnew;
        uint32 oldLen = strlen(oldName) + 1, newLen = strlen(newName) + 1;

        if ( !rename_msg.size ) {
            alloc_xbuf(&rename_msg, 4096);
        }
        if ( rename_msg.size < 2 * sizeof(uint32) + oldLen + newLen + 1024 ) {
            realloc_xbuf(&rename_msg, 2 * sizeof(uint32) + oldLen + newLen + 1024);
        }
        bufP = rename_msg.buf;
        SIVAL(bufP, 0, oldLen);        bufP += sizeof(uint32);
        SIVAL(bufP, 0, newLen);        bufP += sizeof(uint32);
        SIVAL(bufP, 0, file->isTemp);  bufP += sizeof(uint32);
        memcpy(bufP, oldName, oldLen); bufP += oldLen;
        memcpy(bufP, newName, newLen); bufP += newLen;
        bufPnew = (char*)bpc_attrib_file2buf(file, (uchar*)bufP, (uchar*)rename_msg.buf + rename_msg.size);
        if ( bufPnew > rename_msg.buf + rename_msg.size ) {
            ssize_t used = bufP - rename_msg.buf;
            realloc_xbuf(&rename_msg, (bufPnew - rename_msg.buf) + 4096);
            bufPnew = (char*)bpc_attrib_file2buf(file, (uchar*)rename_msg.buf + used, (uchar*)rename_msg.buf + rename_msg.size);
        }
        if ( LogLevel >= 6 ) bpc_logMsgf("Sending rename request (len=%d)\n", bufPnew - rename_msg.buf);
        send_msg(MSG_RENAME, rename_msg.buf, bufPnew - rename_msg.buf, 0);
        bpc_attribCache_setFile(&acNew, (char*)newName, file, 0);
        bpc_attribCache_deleteFile(&acNew, (char*)oldName);
        return 0;
    }

    oldIsTemp = file->isTemp;
    file->isTemp = 0;
    if ( (fileNew = bpc_attribCache_getFile(&acNew, (char*)newName, 0, 0)) ) {
        /*
         * If fileNew is a temporary file, just delete it
         */
        if ( fileNew->isTemp ) {
            bpc_attribCache_deleteFile(&acNew, (char*)newName);
            fileNew = NULL;
        } else {
            /*
             * If newName exists, and has different attributes, then we unlink the file.
             */
            if ( fileNew->nlinks > 0 ) {
                /*
                 * We are updating a file with hardlinks.  unlink() will break the existing hardlink.
                 * Give the oldName a new inode number, so that the hardlink will be re-established later
                 * if the files are still meant to be linked.
                 */
                file->inode      = Stats.InodeCurr;
                Stats.InodeCurr += 2;
            }
            if ( (fileAttrChanged = bpc_attrib_fileCompare(file, fileNew)) ) {
                if ( bpc_unlink(newName) ) return -1;
            }
        }
    }
    if ( file->type == BPC_FTYPE_DIR ) {
        char path[BPC_MAXPATHLEN], pathOld[BPC_MAXPATHLEN];

        bpc_attribCache_getFullMangledPath(&acNew, path, (char*)newName, file->backupNum);
        bpc_attribCache_getFullMangledPath(&acNew, pathOld, (char*)oldName, file->backupNum);

        if ( rename(pathOld, path) ) {
            bpc_logErrf("bpc_rename: directory rename %s -> %s failed\n", pathOld, path);
            errno = EACCES;
            return -1;
        }
    }
    if ( acOldUsed ) {
        if ( !oldIsTemp && !bpc_attribCache_getFile(&acOld, (char*)oldName, 0, 0) ) {
            if ( bpc_attribCache_setFile(&acOld, (char*)oldName, file, 1) > 0 ) {
                bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
            }
        }
        if ( !fileNew && !bpc_attribCache_getFile(&acOld, (char*)newName, 0, 0) ) {
            bpc_attrib_file *fileOld = bpc_attribCache_getFile(&acOld, (char*)newName, 1, 0);
            fileOld->type = BPC_FTYPE_DELETED;
            bpc_attribCache_setFile(&acOld, (char*)newName, fileOld, 0);
        }
    }
    if ( !fileNew || fileAttrChanged ) {
        bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        bpc_attribCache_setFile(&acNew, (char*)newName, file, 0);
    }
    bpc_attribCache_deleteFile(&acNew, (char*)oldName);
    fprintf(stderr, "IOrename: %lu %s%s\n", (unsigned long)strlen(oldName), oldName, newName);
    return 0;
}


int bpc_rename_request(char *oldName, char *newName, uint32 isTemp, char *bufP, char *bufEnd)
{
    bpc_attrib_file *file = bpc_attribCache_getFile(&acNew, (char*)oldName, 1, 0);
    if ( (bufP = (char*)bpc_attrib_buf2fileFull(file, (uchar*)bufP, (uchar*)bufEnd)) != bufEnd ) {
        bpc_logErrf("bpc_rename_request(%s,%s) got to %p vs end = %p\n", oldName, newName, bufP, bufEnd);
    }
    file->isTemp = isTemp;
    return bpc_rename(oldName, newName);
}

int bpc_mknod(const char *fileName, mode_t mode, dev_t dev)
{
    bpc_attrib_file *file;
    int type;
    int ret = 0;
    FdInfo *fd;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_mknod(%s, 0%o, %lu)\n",
                            fileName, mode, (unsigned long)dev);

    if ( (file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0)) ) {
        errno = EEXIST;
        return -1;
    }
    if ( acOldUsed && !bpc_attribCache_getFile(&acOld, (char*)fileName, 0, 0) ) {
        file = bpc_attribCache_getFile(&acOld, (char*)fileName, 1, 0);
        file->type = BPC_FTYPE_DELETED;
        bpc_attribCache_setFile(&acOld, (char*)fileName, file, 0);
    }
    type = BPC_FTYPE_FILE;
    if ( (mode & S_IFMT) == S_IFIFO )  type = BPC_FTYPE_FIFO;
    if ( (mode & S_IFMT) == S_IFBLK )  type = BPC_FTYPE_BLOCKDEV;
    if ( (mode & S_IFMT) == S_IFCHR )  type = BPC_FTYPE_CHARDEV;
    if ( (mode & S_IFMT) == S_IFSOCK ) type = BPC_FTYPE_SOCKET;

    if ( type == BPC_FTYPE_BLOCKDEV || type == BPC_FTYPE_CHARDEV ) {
        char data[BPC_MAXPATHLEN];

        if ( !(fd = bpc_fileOpen(&acNew, (char*)fileName, O_WRONLY | O_CREAT | O_TRUNC)) ) {
            bpc_logErrf("bpc_mknod: open/create of %s failed\n", fileName);
            Stats.ErrorCnt++;
            return -1;
        }
        snprintf(data, sizeof(data), "%lu,%lu", (unsigned long)major(dev), (unsigned long)minor(dev));
        if ( bpc_fileWrite(&acNew, fd, data, strlen(data)) ) {
            bpc_logErrf("bpc_mknod: write failed\n");
            ret = -1;
            Stats.ErrorCnt++;
        }
        if ( bpc_fileClose(&acNew, fd, type, mode & ~S_IFMT, (char*)fileName) ) {
            bpc_logErrf("bpc_mknod: close failed\n");
            ret = -1;
            Stats.ErrorCnt++;
        }
    } else {
        /*
         * empty file - just write attributes
         */
        file = bpc_attribCache_getFile(&acNew, (char*)fileName, 1, 0);
        file->type  = type;
        file->mode  = mode & ~S_IFMT;
        file->inode = Stats.InodeCurr;
        file->size  = 0;
        Stats.InodeCurr  += 2;
        bpc_attribCache_setFile(&acNew, (char*)fileName, file, 0);
        fprintf(stderr, "IOdone: new %s\n", fileName);
    }
    return ret;
}

int bpc_open(const char *fileName, int flags, mode_t mode)
{
    bpc_attrib_file *file;
    FdInfo *fd;

    /*
     * handle a special case of opening a directory.  If a directory
     * is being replaced by a file, the generator has removed the
     * directory already, but we (ie: the receiver) don't know
     * that yet.
     */
    if ( !am_generator && (file = bpc_attribCache_getFile(&acNew, (char*)fileName, 0, 0))
                       && file->type == BPC_FTYPE_DIR ) {
        if ( acOldUsed ) bpc_attribCache_setFile(&acOld, (char*)fileName, file, 1);
        bpc_attribCache_deleteFile(&acNew, (char*)fileName);
        if ( LogLevel >= 4 ) bpc_logMsgf("bpc_open(%s, 0x%x, 0%o) opening directory -> -1\n", fileName, flags, mode);
        return -1;
    }

    if ( !(fd = bpc_fileOpen(&acNew, (char*)fileName, flags)) ) {
        if ( LogLevel >= 4 ) bpc_logMsgf("bpc_open(%s, 0x%x, 0%o) -> -1\n", fileName, flags, mode);
        return -1;
    }
    fd->mode = mode;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_open(%s, 0x%x, 0%o) -> %d\n", fileName, flags, mode, fd->fdNum);

    return fd->fdNum;
}

int bpc_close(int fdNum)
{
    if ( fdNum < 0 || fdNum >= MAX_FD || !Fd[fdNum].used ) {
        errno = EBADF;
        return -1;
    }
    
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_close(%d (%s))\n", fdNum, Fd[fdNum].fileName);

    return bpc_fileClose(&acNew, &Fd[fdNum], -1, -1, NULL);
}

off_t bpc_lseek(int fdNum, off_t offset, int whence)
{
    FdInfo *fd;

    if ( fdNum < 0 || fdNum >= MAX_FD || !Fd[fdNum].used ) {
        errno = EBADF;
        return -1;
    }
    fd = &Fd[fdNum];

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lseek(%d (%s), %lu, %d)\n", fdNum, fd->fileName, offset, whence);

    if ( fd->tmpFd < 0 ) {
        off_t newPosn = -1;

        if ( whence == SEEK_SET )      newPosn = offset;
        else if ( whence == SEEK_CUR ) newPosn = fd->posn + offset;
        else if ( whence == SEEK_END ) newPosn = fd->fileSize + offset;
        if ( newPosn < 0 ) {
            errno = EINVAL;
            return -1;
        }
        if ( (size_t)newPosn < fd->bufferSize ) {
            fd->posn = newPosn;
            return fd->posn;
        }
        /*
         * We need to seek off the end of our in-memory buffer.
         * Switch to a file instead.
         */
        if ( bpc_fileSwitchToDisk(&acNew, fd) ) return -1;
    }
    return lseek(fd->tmpFd, offset, whence);
}

off_t bpc_ftruncate(int fdNum, off_t length)
{
    FdInfo *fd;

    if ( fdNum < 0 || fdNum >= MAX_FD || !Fd[fdNum].used ) {
        errno = EBADF;
        return -1;
    }
    fd = &Fd[fdNum];

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_ftruncate(%d (%s), %lu)\n", fdNum, fd->fileName, length);

    if ( fd->tmpFd < 0 ) {
        if ( length < 0 ) {
            errno = EINVAL;
            return -1;
        }
        if ( length == fd->fileSize ) {
            return 0;
        }
        if ( (size_t)length < fd->bufferSize ) {
            fd->dirty = 1;
            fd->fileSize = length;
            if ( fd->posn > fd->fileSize ) fd->posn = fd->fileSize;
            return 0;
        }
        /*
         * We need to make the file larger than the in-memory buffer.
         * Switch to a file instead.
         */
        if ( bpc_fileSwitchToDisk(&acNew, fd) ) return -1;
    }
    fd->dirty = 1;
    return ftruncate(fd->tmpFd, length);
}

ssize_t bpc_read(int fdNum, void *buf, size_t readSize)
{
    FdInfo *fd;

    if ( fdNum < 0 || fdNum >= MAX_FD || !Fd[fdNum].used ) {
        errno = EBADF;
        return -1;
    }
    fd = &Fd[fdNum];

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_read(%d (%s), buf, %lu)\n",
                                    fdNum, fd->fileName, readSize);

    if ( fd->tmpFd < 0 ) {
        if ( readSize > (size_t)fd->fileSize - fd->posn ) readSize = fd->fileSize - fd->posn;
        memcpy(buf, fd->buffer + fd->posn, readSize);
        fd->posn += readSize;
        return readSize;
    } else {
        return read(fd->tmpFd, buf, readSize);
    }
}

ssize_t bpc_write(int fdNum, const void *buf, size_t writeSize)
{
    FdInfo *fd;

    if ( fdNum < 0 || fdNum >= MAX_FD || !Fd[fdNum].used ) {
        errno = EBADF;
        return -1;
    }
    fd = &Fd[fdNum];

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_write(%d (%s), buf, %lu)\n",
                                    fdNum, fd->fileName, writeSize);

    if ( bpc_fileWrite(&acNew, fd, (char*)buf, writeSize) ) return -1;
    return writeSize;
}

ssize_t bpc_readlink(const char *fileName, char *buffer, size_t bufferSize)
{
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_readlink(%s, buf, %lu)\n",
                                    fileName, bufferSize);

    return bpc_fileReadAll(&acNew, (char*)fileName, buffer, bufferSize);
}

int bpc_chdir(const char *dirName)
{
    bpc_attrib_file *file;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_chdir(%s)\n", dirName);

    if ( !(file = bpc_attribCache_getFile(&acNew, (char*)dirName, 0, 0)) || file->type != BPC_FTYPE_DIR ) {
        errno = ENOENT;
        return -1;
    }
    bpc_attribCache_setCurrentDirectory(&acNew, (char*)dirName);
    if ( acOldUsed ) bpc_attribCache_setCurrentDirectory(&acOld, (char*)dirName);
    return 0;
}

int bpc_mkdir(const char *dirName, mode_t mode)
{
    char path[BPC_MAXPATHLEN];
    bpc_attrib_file *file;
    int ret;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_mkdir(%s, 0%o)\n", dirName, mode);

    bpc_attribCache_getFullMangledPath(&acNew, path, (char*)dirName, -1);
    if ( bpc_attribCache_getFile(&acNew, (char*)dirName, 0, 0) ) {
        errno = EEXIST;
        return -1;
    }

    if ( acOldUsed && !bpc_attribCache_getFile(&acOld, (char*)dirName, 0, 0) ) {
        file = bpc_attribCache_getFile(&acOld, (char*)dirName, 1, 0);
        file->type = BPC_FTYPE_DELETED;
        bpc_attribCache_setFile(&acOld, (char*)dirName, file, 0);
    }
    if ( (ret = bpc_path_create(path)) ) return ret;
    file = bpc_attribCache_getFile(&acNew, (char*)dirName, 1, 0);
    file->type  = BPC_FTYPE_DIR;
    file->mode  = mode;
    file->inode = Stats.InodeCurr;
    Stats.InodeCurr += 2;
    bpc_attribCache_setFile(&acNew, (char*)dirName, file, 0);
    if ( !*dirName ) {
        fprintf(stderr, "IOdone: new .\n");
    } else {
        fprintf(stderr, "IOdone: new %s\n", dirName);
    }
    return 0;
}

int bpc_rmdir(const char *dirName)
{
    char path[BPC_MAXPATHLEN];
    bpc_attrib_file *file;
    STRUCT_STAT st;
    int statOk, cnt;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_rmdir(%s)\n", dirName);

    file = bpc_attribCache_getFile(&acNew, (char*)dirName, 0, 0);
    bpc_attribCache_getFullMangledPath(&acNew, path, (char*)dirName, file->backupNum);

    statOk = !stat(path, &st);
    if ( file && (!statOk || !S_ISDIR(st.st_mode)) ) {
        errno = ENOTDIR;
        return -1;
    }
    if ( !file || (!statOk || !S_ISDIR(st.st_mode)) ) {
        errno = ENOENT;
        return -1;
    }
    if ( (cnt = bpc_attribCache_getDirEntryCnt(&acNew, (char*)dirName)) > 0 ) {
        errno = ENOTEMPTY;
        return -1;
    }

    /*
     * Remove the directory (and update reference counts).  We need
     * to first flush the attrib cache below this directory.
     * If this directory is older than this backup, then move the
     * attributes to old.
     *
     * TODO: is dirName in the right charset?
     */
    bpc_attribCache_flush(&acNew, 0, (char*)dirName);
    bpc_path_remove(path, acNew.compress);
    if ( file && file->inode < Stats.Inode0 && acOldUsed && !bpc_attribCache_getFile(&acOld, (char*)dirName, 0, 0) ) {
        bpc_attribCache_setFile(&acOld, (char*)dirName, file, 0);
    }
    bpc_attribCache_deleteFile(&acNew, (char*)dirName);
    return 0;
}

DIR *bpc_opendir(const char *path)
{
    my_DIR *d;
    ssize_t entrySize;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_opendir(%s)\n", path);

    /*
     * Get the total number of bytes needed to store all the file names and inode numbers
     */
    if ( (entrySize = bpc_attribCache_getDirEntries(&acNew, (char*)path, NULL, 0)) < 0 ) return NULL;

    if ( !(d = calloc(1, sizeof(my_DIR))) ) return NULL;
    if ( !(d->entries = malloc(entrySize)) ) {
        free(d);
        return NULL;
    }

    /*
     * Now populate entries with all the file names, each NULL terminated, followed by the inode number.
     */
    d->entrySize = entrySize;
    if ( bpc_attribCache_getDirEntries(&acNew, (char*)path, d->entries, d->entrySize) != d->entrySize ) {
        free(d);
        free(d->entries);
        return NULL;
    }
    d->entryIdx = 0;
    return (DIR*)d;
}

struct dirent *bpc_readdir(DIR *dir)
{
    my_DIR *d = (my_DIR*)dir;

    if ( d->entryIdx >= d->entrySize ) {
        if ( LogLevel >= 4 ) bpc_logMsgf("bpc_readdir -> NULL\n");
        return NULL;
    }

    strncpy(d->dirent.d_name, d->entries + d->entryIdx, sizeof(d->dirent.d_name));
    d->dirent.d_name[sizeof(d->dirent.d_name)-1] = '\0';
    d->entryIdx += strlen(d->entries + d->entryIdx) + 1;
    memcpy(&d->dirent.d_ino, d->entries + d->entryIdx, sizeof(ino_t));
    d->entryIdx += sizeof(ino_t);
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_readdir -> %s\n", d->dirent.d_name);
    return &d->dirent;
}

int bpc_closedir(DIR *dir)
{
    my_DIR *d = (my_DIR*)dir;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_closedir()\n");

    if ( d->entries) free(d->entries);
    free(d);
    return 0;
}

/* 
 * xattr handling
 */
ssize_t bpc_lgetxattr(const char *path, const char *name, void *value, size_t size)
{
    bpc_attrib_file *file = bpc_attribCache_getFile(&acNew, (char*)path, 0, 0);
    bpc_attrib_xattr *xattr;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lgetxattr(%s, %s)\n", path, name);

    if ( !file ) {
        errno = ENOENT;
        return -1;
    }
    if ( !(xattr = bpc_attrib_xattrGet(file, (char*)name, strlen(name) + 1, 0)) ) {
        errno = ENOENT;
        return -1;
    }
    if ( !value ) return xattr->valueLen;
    if ( xattr->valueLen <= size ) {
        memcpy(value, xattr->value, xattr->valueLen);
        return xattr->valueLen;
    } else {
        memcpy(value, xattr->value, size);
        return size;
    }
}

ssize_t bpc_fgetxattr(int filedes, const char *name, void *value, size_t size)
{
    if ( filedes < 0 || filedes >= MAX_FD || !Fd[filedes].used ) {
        errno = EBADF;
        return -1;
    }

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_fgetxattr(%d (%s), %s)\n", filedes, Fd[filedes].fileName, name);

    return bpc_lgetxattr(Fd[filedes].fileName, name, value, size);
}

int bpc_lsetxattr(const char *path, const char *name, const void *value, size_t size, UNUSED(int flags))
{
    int ret;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lsetxattr(%s, %s)\n", path, name);

    bpc_attrib_file *file = bpc_attribCache_getFile(&acNew, (char*)path, 0, 0);
    bpc_attrib_xattr *xattr;

    if ( !file ) {
        errno = ENOENT;
        return -1;
    }

    /*
     * Check if the attribute is unchanged (we can't just call bpc_attribCache_setFile(), 
     * since it updates in place, meaning we then don't have the original version).
     */
    if ( (xattr = bpc_attrib_xattrGet(file, (char*)name, strlen(name) + 1, 0)) ) {
        if ( xattr->valueLen == size && !memcmp(xattr->value, value, xattr->valueLen) ) {
            if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lsetxattr(%s, %s) unchanged\n", path, name);
            return 0;
        }
    }

    /*
     * Save away the attributes in old if not recently set and not present already
     */
    if ( acOldUsed && !file->isTemp && file->inode < Stats.Inode0 && !bpc_attribCache_getFile(&acOld, (char*)path, 0, 0) ) {
        if ( bpc_attribCache_setFile(&acOld, (char*)path, file, 1) > 0 ) {
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        }
    }

    /*
     * now set the new attribute value
     */
    if ( (ret = bpc_attrib_xattrSetValue(file, (char*)name, strlen(name) + 1, (void*)value, size)) < 0 ) {
        if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lsetxattr(%s, %s) -> return %d\n", path, name, ret);
        return ret;
    }
    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lsetxattr(%s, %s) -> return %d\n", path, name, 0);
    return 0;
}

int bpc_lremovexattr(const char *path, const char *name)
{
    bpc_attrib_file *file = bpc_attribCache_getFile(&acNew, (char*)path, 0, 0);
    bpc_attrib_xattr *xattr;

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_lremovexattr(%s, %s)\n", path, name);

    if ( !file ) {
        errno = ENOENT;
        return -1;
    }

    /*
     * Check if the attribute is exists - if not then quietly return.
     */
    if ( !(xattr = bpc_attrib_xattrGet(file, (char*)name, strlen(name) + 1, 0)) ) return 0;

    /*
     * Save away the attributes in old if not recently set and not present already
     */
    if ( acOldUsed && !file->isTemp && file->inode < Stats.Inode0 && !bpc_attribCache_getFile(&acOld, (char*)path, 0, 0) ) {
        if ( bpc_attribCache_setFile(&acOld, (char*)path, file, 1) > 0 ) {
            bpc_poolRefDeltaUpdate(file->compress, &file->digest, 1);
        }
    }

    /*
     * now remove the attribute
     */
    return bpc_attrib_xattrDelete(file, (char*)name, strlen(name) + 1);
}

ssize_t bpc_llistxattr(const char *path, char *list, size_t size)
{
    bpc_attrib_file *file = bpc_attribCache_getFile(&acNew, (char*)path, 0, 0);

    if ( LogLevel >= 4 ) bpc_logMsgf("bpc_llistxattr(%s)\n", path);

    if ( !file ) {
        errno = ENOENT;
        return -1;
    }
    return bpc_attrib_xattrList(file, list, size, 1);
}
