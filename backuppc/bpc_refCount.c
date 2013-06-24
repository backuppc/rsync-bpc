/*
 * Routines to provide reference counting
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
 * magic number that appears at the start of the reference count (or delta count file)
 */
#define BPC_POOL_REF_MAGIC    (0x178e553c)

#define CONV_BUF_TO_UINT32(buf)    ((buf)[0] << 24 | (buf)[1] << 16 | (buf)[2] << 8 | (buf)[3])

#define CONV_UINT32_TO_BUF(buf, val)   { *(buf)++ = ((val) >> 24) & 0xff;               \
                                         *(buf)++ = ((val) >> 16) & 0xff;               \
                                         *(buf)++ = ((val) >> 8)  & 0xff;               \
                                         *(buf)++ = ((val) >> 0)  & 0xff; }

typedef struct {
    bpc_hashtable_key key;
    int32 count;
    bpc_digest digest;
} DigestInfo;

typedef struct {
    int fd;
    uchar *bufP;
    int errorCnt;
    uchar buf[4 * 65536];
} write_info;

void bpc_poolRefInit(bpc_refCount_info *info, int entryCnt)
{
    bpc_hashtable_create(&info->ht, entryCnt, sizeof(DigestInfo));
}

void bpc_poolRefDestroy(bpc_refCount_info *info)
{
    bpc_hashtable_destroy(&info->ht);
}

void bpc_poolRefSet(bpc_refCount_info *info, bpc_digest *digest, int32 count)
{
    DigestInfo *d = bpc_hashtable_find(&info->ht, digest->digest, digest->len, 1);
    if ( d->key.key == digest ) {
        /*
         * new entry - copy in digest
         */
        d->digest  = *digest;
        d->key.key = d->digest.digest;
    }
    d->count = count;
    return;
}

int bpc_poolRefGet(bpc_refCount_info *info, bpc_digest *digest, int32 *count)
{

    DigestInfo *d = bpc_hashtable_find(&info->ht, digest->digest, digest->len, 0);
    if ( !d ) return -1;
    *count = d->count;
    return 0;
}

int bpc_poolRefDelete(bpc_refCount_info *info, bpc_digest *digest)
{
    DigestInfo *d = bpc_hashtable_find(&info->ht, digest->digest, digest->len, 0);
    if ( !d ) return -1;
    bpc_hashtable_nodeDelete(&info->ht, d);
    return 0;
}

int bpc_poolRefIncr(bpc_refCount_info *info, bpc_digest *digest, int32 delta)
{
    DigestInfo *d = bpc_hashtable_find(&info->ht, digest->digest, digest->len, 1);
    if ( d->key.key == digest ) {
        /*
         * new entry - copy in digest
         */
        d->digest  = *digest;
        d->key.key = d->digest.digest;
    }
    d->count += delta;
    if ( BPC_LogLevel >= 8 ) {
        char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];

        bpc_digest_digest2str(&d->digest, hexStr);
        bpc_logMsgf("bpc_poolRefIncr(%s, %d), count now %d\n", hexStr, delta, d->count);
    }
    return d->count;
}

int bpc_poolRefIterate(bpc_refCount_info *info, bpc_digest *digest, int32 *count, uint *idx)
{
    DigestInfo *d = bpc_hashtable_nextEntry(&info->ht, idx);
    if ( !d ) return -1;
    *digest = d->digest;
    *count  = d->count;
    return 0;
}

void bpc_poolRefPrintEntry(DigestInfo *info)
{
    char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];

    bpc_digest_digest2str(&info->digest, hexStr);
    fprintf(stderr, "%-20s %d\n", hexStr, info->count);
}

void bpc_poolRefCountPrint(bpc_refCount_info *info)
{
    bpc_hashtable_iterate(&info->ht, (void*)bpc_poolRefPrintEntry, NULL);
}

static void write_file_flush(write_info *out)
{
    uchar *p = out->buf;
    while ( p < out->bufP ) {
        int nWrite = write(out->fd, p, out->bufP - p);
        if ( nWrite < 0 ) {
            if ( errno == EINTR ) continue;
            out->errorCnt++;
            return;
        }
        p += nWrite;
    }
    out->bufP = out->buf;
}

static int bpc_poolRef_read_more_data(int fd, uchar *buf, size_t bufSize, size_t *nRead, uchar **bufPP, char *fileName)
{
    int thisRead;

    /*
     * move the remaining part of the buffer down, and read more data
     */
    *nRead = (buf + *nRead) - *bufPP;
    if ( *nRead > 0 ) memmove(buf, *bufPP, *nRead);
    *bufPP = buf;
    do {
        do {
            thisRead = read(fd, buf + *nRead, bufSize - *nRead);
        } while ( thisRead < 0 && errno == EINTR );
        if ( thisRead < 0 ) {
            bpc_logErrf("bpc_poolRefFileRead: can't read more bytes from %s (errno %d)\n", fileName, errno);
            return -1;
        }
        if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_poolRef_read_more_data: read %d bytes (nRead = %d, sizeof(buf) = %d)\n", thisRead, *nRead, bufSize);
        *nRead += thisRead;
    } while ( thisRead > 0 && *nRead < sizeof(buf) );
    return 0;
}

/*
 * Read variable-length unsigned integer in 7 bit chunks, LSB first.
 *
 * To handle signed numbers, the very first LSB is a sign bit, meaning the first byte
 * stores just 6 bits.
 */
static int64 getVarInt(uchar **bufPP, uchar *bufLast)
{
    int64 result = 0;
    uchar *bufP = *bufPP, c = '\0';
    int i = 6, negative = 0;

    if ( bufP < bufLast ) {
        c = *bufP++;
        negative = c & 0x1;
        result = (c & 0x7e) >> 1;
    }
    while ( bufP < bufLast && (c & 0x80) ) {
        c = *bufP++;
        result |= (c & 0x7f) << i;
        i += 7;
    }
    *bufPP = bufP;
    if ( negative ) result = -result;
    return result;
}

/*
 * Write variable-length unsigned integer in 7 bit chunks, LSB first.
 *
 * To handle signed numbers, the very first LSB is a sign bit, meaning the first byte
 * stores just 6 bits.
 */
static void setVarInt(uchar **bufPP, uchar *bufLast, int64 value)
{
    uchar *bufP = *bufPP;
    int negative = 0;

    if ( value < 0 ) {
        value = -value;
        negative = 1;
    }
    if ( bufP < bufLast ) {
        uchar c = ((value & 0x3f) << 1) | negative;
        value >>= 6;
        if ( value ) c |= 0x80;
        *bufP++ = c;
    }
    while ( value && bufP < bufLast ) {
        uchar c = value & 0x7f;
        value >>= 7;
        if ( value ) c |= 0x80;
        *bufP++ = c;
    }
    *bufPP = bufP;
}

static void bpc_poolRefFileWriteEntry(DigestInfo *info, write_info *out)
{
    if ( out->bufP > out->buf + sizeof(out->buf) - BPC_DIGEST_LEN_MAX - 16 ) write_file_flush(out);
    *out->bufP++ = (uchar)info->digest.len;
    memcpy(out->bufP, info->digest.digest, info->digest.len);
    out->bufP += info->digest.len;
    setVarInt(&out->bufP, out->buf + sizeof(out->buf), info->count);
}

/*
 * Write a pool reference file from the hash table.
 */
int bpc_poolRefFileWrite(bpc_refCount_info *info, char *fileName)
{
    write_info out;

    out.errorCnt = 0;
    out.bufP     = out.buf;
    out.fd       = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if ( out.fd < 0 ) {
        /*
         * Maybe the directory doesn't exist - try to create it and try again
         */
        char dir[BPC_MAXPATHLEN], *p;

        snprintf(dir, sizeof(dir), "%s", fileName);
        if ( (p = strrchr(dir, '/')) ) {
            *p = '\0';
            bpc_path_create(dir);
            out.fd = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        }
        if ( out.fd < 0 ) {
            bpc_logErrf("bpc_poolRefDeltaFileFlush: can't open/create pool delta file name %s (errno %d)\n", fileName, errno);
            out.errorCnt++;
            return out.errorCnt;
        }
    }

    /*
     * start with the magic number, then the total number of entries
     */
    CONV_UINT32_TO_BUF(out.bufP, BPC_POOL_REF_MAGIC);
    setVarInt(&out.bufP, out.buf + sizeof(out.buf), bpc_hashtable_entryCount(&info->ht));

    /*
     * now write all the digests and counts
     */
    bpc_hashtable_iterate(&info->ht, (void*)bpc_poolRefFileWriteEntry, &out);

    if ( out.bufP > out.buf ) write_file_flush(&out);
    if ( close(out.fd) < 0 ) {
        bpc_logErrf("bpc_poolRefDeltaFileFlush: pool delta close failed to %s (errno %d)\n", fileName, errno);
        out.errorCnt++;
    }
    return out.errorCnt;
}

/*
 * Read a pool reference file into the hash table, which should be already initialized.
 */
int bpc_poolRefFileRead(bpc_refCount_info *info, char *fileName)
{
    int fd = open(fileName, O_RDONLY);
    uint32 entryCnt, i;
    bpc_digest digest;
    int64 count;
    size_t nRead = 0;
    uint32 magic;
    uchar buf[8 * 65536];
    uchar *bufP = buf;

    if ( fd < 0 ) {
        bpc_logErrf("bpc_poolRefFileRead: can't open %s (errno %d)\n", fileName, errno);
        return -1;
    }
    if ( bpc_poolRef_read_more_data(fd, buf, sizeof(buf), &nRead, &bufP, fileName) < 0 ) {
        bpc_logErrf("bpc_poolRefFileRead: can't read data from %s (errno %d)\n", fileName, errno);
        return -1;
    }
    magic = CONV_BUF_TO_UINT32(bufP);
    bufP += 4;

    if ( magic != BPC_POOL_REF_MAGIC ) {
        bpc_logErrf("bpc_poolRefFileRead: bad magic number 0x%x (expected 0x%x)\n", magic, BPC_POOL_REF_MAGIC);
        return -1;
    }

    entryCnt = getVarInt(&bufP, buf + nRead);
    if ( BPC_LogLevel >= 4 ) bpc_logMsgf("bpc_poolRefFileRead: got %d entries (nRead = %d)\n", entryCnt, nRead);
    /*
     * make sure the hash table is big enough in one go to avoid multiple doublings
     */
    bpc_hashtable_growSize(&info->ht, entryCnt * 4 / 3);

    for ( i = 0 ; i < entryCnt ; i++ ) {
        DigestInfo *digestInfo;

        if ( nRead == sizeof(buf) && bufP > buf + nRead - 64
                && bpc_poolRef_read_more_data(fd, buf, sizeof(buf), &nRead, &bufP, fileName) < 0 ) {
            bpc_logErrf("bpc_poolRefFileRead: can't read more data from %s (errno %d)\n", fileName, errno);
            return -1;
        }
        digest.len = *bufP++;
        if ( digest.len > (int)sizeof(digest.digest) ) digest.len = sizeof(digest.digest);
        memcpy(digest.digest, bufP, digest.len);
        bufP += digest.len;
        count = getVarInt(&bufP, buf + nRead);

        if ( BPC_LogLevel >= 7 ) bpc_logMsgf("bpc_poolRefFileRead: entry %d: digest len = %d, digest = 0x%02x%02x%02x...., count = %d\n",
                                              i, digest.len, digest.digest[0], digest.digest[1], digest.digest[2], count);

        digestInfo = bpc_hashtable_find(&info->ht, digest.digest, digest.len, 1);

        if ( digestInfo->key.key == digest.digest ) {
            /*
             * new entry since the key points to our key - copy info into new node and set key locally
             */
            digestInfo->digest  = digest;
            digestInfo->key.key = digestInfo->digest.digest;
        }
        digestInfo->count = count;
    }

    close(fd);

    return 0;
}

/***********************************************************************
 * Reference count deltas - we maintain two hash tables for uncompressed
 * and compressed deltas.
 ***********************************************************************/

static bpc_refCount_info DigestHT[2];

static char   *HostDir      = NULL;
static int    OutputFileCnt = 0;

void bpc_poolRefDeltaFileInit(char *hostDir)
{
    HostDir = hostDir;
    bpc_poolRefInit(&DigestHT[0], 256);
    bpc_poolRefInit(&DigestHT[1], 1 << 20);
    DigestHT[0].initDone = DigestHT[1].initDone = 1;
}

uint32 bpc_poolRefDeltaFileFlush(void)
{
    char tempFileName[BPC_MAXPATHLEN], finalFileName[BPC_MAXPATHLEN];
    int compress;
    int errorCnt = 0;
    int fd;

    if ( !DigestHT[0].initDone ) return 1;
    for ( compress = 0 ; compress < 2 ; compress++ ) {
        uint entryCnt = bpc_hashtable_entryCount(&DigestHT[compress].ht);

        if ( entryCnt == 0 ) continue;

        do {
            if ( snprintf(tempFileName, sizeof(tempFileName), "%s/refCnt/tpoolCntDelta_%d_%d_%d_%d",
                          HostDir, compress, BPC_TmpFileUnique, OutputFileCnt, getpid()) >= (int)sizeof(tempFileName) - 1 ) {
                bpc_logErrf("bpc_poolRefDeltaFileFlush: pool delta file name %s truncated\n", tempFileName);
                errorCnt++;
            }
            if ( (fd = open(tempFileName, O_RDONLY, 0666)) >= 0 ) {
                close(fd);
                OutputFileCnt++;
            }
        } while ( fd >= 0 );

        errorCnt += bpc_poolRefFileWrite(&DigestHT[compress], tempFileName);

        if ( snprintf(finalFileName, sizeof(finalFileName), "%s/refCnt/poolCntDelta_%d_%d_%d_%d",
                      HostDir, compress, BPC_TmpFileUnique >= 0 ? BPC_TmpFileUnique : 0,
                      OutputFileCnt, getpid()) >= (int)sizeof(finalFileName) - 1 ) {
            bpc_logErrf("bpc_poolRefDeltaFileFlush: pool delta file name %s truncated\n", finalFileName);
            errorCnt++;
        }
        if ( errorCnt ) {
            unlink(tempFileName);
            continue;
        }
        if ( rename(tempFileName, finalFileName) != 0 ) {
            bpc_logErrf("bpc_poolRefDeltaFileFlush: can't rename %s to %s (errno %d)\n", tempFileName, finalFileName, errno);
            unlink(tempFileName);
            errorCnt++;
        }
        if ( !errorCnt ) {
            bpc_hashtable_erase(&DigestHT[compress].ht);
        }
    }
    OutputFileCnt++;
    if ( errorCnt ) {
        /*
         * Need to fsck this host
         */
        bpc_poolRefRequestFsck(HostDir, 1);
    }
    return errorCnt;
}

/*
 * Mark this host as needing an fsck.  Multiple requests can be supported with unique
 * numbers.  ext == 0 is used for the overall backup process, and it is removed when
 * the backup finished.  Various errors can use other extensions.  If any files are
 * present, an fsck is done either by the next backup, BackupPC_refCountUpdate or
 * BackupPC_fsck.
 */
void bpc_poolRefRequestFsck(char *hostDir, int ext)
{
    char fileName[BPC_MAXPATHLEN];
    int fd;

    snprintf(fileName, sizeof(fileName), "%s/refCnt/needFsck%d", hostDir, ext);
    if ( (fd = open(fileName, O_CREAT | O_WRONLY, 0660)) < 0 ) {
        bpc_logErrf("bpc_poolRefRequestFsck: can't open/create fsck request file %s (errno %d)\n", fileName, errno);
    }
}

/*
 * Increment/decrement the reference count for the given digest
 */
void bpc_poolRefDeltaUpdate(int compress, bpc_digest *digest, int32 count)
{
    DigestInfo *digestInfo;

    if ( !digest || digest->len == 0 ) return;
    if ( !DigestHT[0].initDone ) return;

    digestInfo = bpc_hashtable_find(&DigestHT[compress ? 1 : 0].ht, digest->digest, digest->len, 1);
    if ( digestInfo->key.key == digest->digest ) {
        /*
         * new entry since the key points to our key - copy info into new node and set key locally
         */
        digestInfo->digest  = *digest;
        digestInfo->key.key = digestInfo->digest.digest;
    }
    digestInfo->count += count;
    if ( BPC_LogLevel >= 8 ) {
        char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];

        bpc_digest_digest2str(&digestInfo->digest, hexStr);
        bpc_logMsgf("bpc_poolRefDeltaUpdate(%s, %d), count now %d\n", hexStr, count, digestInfo->count);
    }
    if ( bpc_hashtable_entryCount(&DigestHT[compress ? 1 : 0].ht) > (1 << 20) ) {
        bpc_poolRefDeltaFileFlush();
    }
}

void bpc_poolRefDeltaPrint(void)
{
    if ( !DigestHT[0].initDone ) return;
    fprintf(stderr, "Uncompressed HT:\n");
    bpc_hashtable_iterate(&DigestHT[0].ht, (void*)bpc_poolRefPrintEntry, NULL);
    fprintf(stderr, "Compressed HT:\n");
    bpc_hashtable_iterate(&DigestHT[1].ht, (void*)bpc_poolRefPrintEntry, NULL);
}
