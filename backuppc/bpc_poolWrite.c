/*
 * Routines for matching and writing files in the pool.
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


static uint32 PoolWriteCnt = 0;

/*
 * Buffer used in various places for copying, comparing etc
 */
#define COMPARE_BUF_SZ     (1 << 19)     /* 0.5 MB */
static uchar TempBuf[2 * COMPARE_BUF_SZ];

int bpc_poolWrite_open(bpc_poolWrite_info *info, int compress, bpc_digest *digest)
{
    int i;

    info->compress      = compress;
    info->eof           = 0;
    info->errorCnt      = 0;
    info->state         = 0;
    info->bufferIdx     = 0;
    info->fileSize      = 0;
    info->matchPosn     = 0;
    info->candidateList = NULL;
    info->fdOpen        = 0;
    info->retValue      = -1;
    info->poolFileSize  = 0;
    info->retryCnt      = 0;
    info->digestExtOpen = -1;
    info->digestExtZeroLen = -1;
    for ( i = 0 ; i < BPC_POOL_WRITE_CONCURRENT_MATCH ; i++ ) {
        info->match[i].used = 0;
    }
    info->buffer        = malloc(BPC_POOL_WRITE_BUF_SZ);
    if ( !info->buffer ) {
        bpc_logErrf("bpc_poolWrite_open: can't allocate %d bytes for buffer\n", BPC_POOL_WRITE_BUF_SZ);
        return -1;
    }
    if ( digest ) {
        info->digest = *digest;
        /* TODO: don't have V3 digest at this point! */
        info->state = 2;
    } else {
        info->digest.len = 0;
    }
    info->digest_v3.len = 0;
    if ( snprintf(info->tmpFileName, sizeof(info->tmpFileName), "%s/%d.%d.%d",
                compress ? BPC_CPoolDir : BPC_PoolDir, (int)getpid(), PoolWriteCnt++,
                BPC_TmpFileUnique >= 0 ? BPC_TmpFileUnique : 0) >= (int)sizeof(info->tmpFileName) - 1 ) {
        bpc_logErrf("bpc_poolWrite_open: file name too long %s\n", info->tmpFileName);
        return -1;
    }
    return 0;
}

/*
 * Fill out the array of candidate matching files.  Returns the number of active
 * matching files.
 */
static int bpc_poolWrite_updateMatches(bpc_poolWrite_info *info)
{
    int i, nMatch = 0;

    for ( i = 0 ; i < BPC_POOL_WRITE_CONCURRENT_MATCH ; i++ ) {
        if ( info->match[i].used ) {
            nMatch++;
            continue;
        }
        while ( info->candidateList ) {
            int match = 1;
            bpc_candidate_file *candidateFile;

            candidateFile = info->candidateList;
            info->candidateList = candidateFile->next;
            if ( bpc_fileZIO_open(&info->match[i].fd, candidateFile->fileName, 0, info->compress) ) {
                info->errorCnt++;
                bpc_logErrf("bpc_poolWrite_updateMatches: can't open candidate file %s for read\n",
                                            candidateFile->fileName);
                free(candidateFile);
                continue;
            }
            /*
             * We need to check that the first info->matchPosn bytes of the candidate file match
             * the original file.
             */
            if ( info->matchPosn > 0 ) {
                if ( info->fdOpen ) {
                    /*
                     * Compare the candidate file against the data in the file
                     */
                    uchar *buf0 = TempBuf;
                    uchar *buf1 = TempBuf + COMPARE_BUF_SZ;
                    OFF_T idx = 0;

                    bpc_fileZIO_rewind(&info->fd);
                    while ( idx < info->matchPosn ) {
                        OFF_T thisRead = info->matchPosn - idx;
                        OFF_T nread0, nread1;

                        if ( thisRead > COMPARE_BUF_SZ ) thisRead = COMPARE_BUF_SZ;
                        nread0 = bpc_fileZIO_read(&info->fd, buf0, thisRead);
                        nread1 = bpc_fileZIO_read(&info->match[i].fd, buf1, thisRead);
                        if ( nread0 != nread1 || memcmp(buf0, buf1, nread0) ) {
                            /*
                             * Need to keep reading the original file to get back to matchPosn
                             */
                            match = 0;
                        }
                        idx += nread0;
                    }
                } else {
                    /*
                     * Compare the candidate file against the data in the buffer
                     */
                    uchar *buf1 = TempBuf;
                    OFF_T idx = 0;

                    while ( idx < info->matchPosn ) {
                        OFF_T thisRead = info->matchPosn - idx;
                        OFF_T nread1;

                        if ( thisRead > COMPARE_BUF_SZ ) thisRead = COMPARE_BUF_SZ;
                        if ( thisRead > info->bufferIdx - idx ) thisRead = info->bufferIdx - idx;
                        nread1 = bpc_fileZIO_read(&info->match[i].fd, buf1, thisRead);
                        if ( thisRead != nread1 || memcmp(info->buffer + idx, buf1, thisRead) ) {
                            match = 0;
                            break;
                        }
                        idx += thisRead;
                    }
                }
            }
            if ( !match ) {
                if ( BPC_LogLevel >= 8 ) bpc_logMsgf("Discarding %s since it doesn't match starting portion\n", candidateFile->fileName);
                bpc_fileZIO_close(&info->match[i].fd);
                free(candidateFile);
                continue;
            }
            info->match[i].used     = 1;
            info->match[i].digest   = candidateFile->digest;
            info->match[i].v3File   = candidateFile->v3File;
            info->match[i].fileSize = candidateFile->fileSize;
            strcpy(info->match[i].fileName, candidateFile->fileName);
            nMatch++;
            if ( BPC_LogLevel >= 9 ) bpc_logMsgf("match[%d] now set to %s\n", i, info->match[i].fileName);
            free(candidateFile);
            break;
        }
    }
    return nMatch;
}

/*
 * Write a chunk to the current pool file.
 *
 * Call with undef to indicate EOF / close.
 */
int bpc_poolWrite_write(bpc_poolWrite_info *info, uchar *data, size_t dataLen)
{
    if ( info->errorCnt ) return -1;

    info->fileSize += dataLen;
    
    if ( info->state == 0 ) {
        /*
         * In this state we are at the start of the file and don't have a digest yet
         */
        if ( data ) {
            /*
             * Cumulate small writes at the start of the file
             */
            if ( info->bufferIdx + dataLen <= BPC_POOL_WRITE_BUF_SZ ) {
                memcpy(info->buffer + info->bufferIdx, data, dataLen);
                info->bufferIdx += dataLen;
                return 0;
            }

            /*
             * We have more data than the buffer can fit.  Top off the buffer if it has less than
             * 1MB of data so that we can compute the V3 digest.
             */
            if ( data && info->bufferIdx < (1 << 20) && BPC_POOL_WRITE_BUF_SZ >= (1 << 20) ) {
                uint32 addTo1MB = (1 << 20) - info->bufferIdx;
                memcpy(info->buffer + info->bufferIdx, data, addTo1MB);
                info->bufferIdx += addTo1MB;
                data            += addTo1MB;
                dataLen         -= addTo1MB;
            }

            if ( !info->digest.len ) {
                ssize_t writeRet;
                /*
                 * We don't have a digest and the file is bigger than the buffer.
                 * So we need to write the data to a temp file and compute the MD5
                 * digest as we write the file.
                 */
                if ( bpc_fileZIO_open(&info->fd, info->tmpFileName, 1, info->compress) ) {
                    info->errorCnt++;
                    bpc_logErrf("bpc_poolWrite_write: can't open/create %s for writing", info->tmpFileName);
                    return -1;
                }
                info->fdOpen = 1;
                md5_begin(&info->md5);
                if ( info->bufferIdx > 0 ) {
                    if ( (writeRet = bpc_fileZIO_write(&info->fd, info->buffer, info->bufferIdx)) != info->bufferIdx ) {
                        info->errorCnt++;
                        bpc_logErrf("bpc_poolWrite_write: write of %lu bytes to %s failed, return = %d",
                                                    (unsigned long)info->bufferIdx, info->tmpFileName, (int)writeRet);
                        return -1;
                    }
                    md5_update(&info->md5, info->buffer, info->bufferIdx);
                }
                info->state = 1;
            } else {
                /*
                 * We have the new digest, so figure out the list of candidate matching files
                 */
                /* TODO: don't have V3 digest at this point! */
                info->state = 2;
            }
        } else {
            /*
             * We are at EOF, so we can compute the digests based on the entire file in
             * the buffer.
            */
            info->eof = 1;
            bpc_digest_buffer2MD5(&info->digest, info->buffer, info->bufferIdx);
            if ( BPC_PoolV3Enabled ) {
                bpc_digest_buffer2MD5_v3(&info->digest_v3, info->buffer, info->bufferIdx);
                if ( BPC_LogLevel >= 8 ) {
                    char hexStr_v3[BPC_DIGEST_LEN_MAX * 2 + 1], hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];
                    bpc_digest_digest2str(&info->digest,    hexStr);
                    bpc_digest_digest2str(&info->digest_v3, hexStr_v3);
                    bpc_logMsgf("bpc_poolWrite_write: digest is %s, v3 is %s\n", hexStr, hexStr_v3);
                }
            } else if ( BPC_LogLevel >= 8 ) {
                char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];
                bpc_digest_digest2str(&info->digest, hexStr);
                bpc_logMsgf("bpc_poolWrite_write: digest is %s\n", hexStr);
            }
            info->state = 2;
        }
    }
    if ( info->state == 1 ) {
        ssize_t writeRet;
        /*
         * In this state we are writing the data to a compressed temporary file, and
         * accumulating the digests.
         */
        if ( dataLen > 0 ) {
            if ( (writeRet = bpc_fileZIO_write(&info->fd, data, dataLen)) != (ssize_t)dataLen ) {
                info->errorCnt++;
                bpc_logErrf("bpc_poolWrite_write: write of %lu bytes to %s failed, return = %d",
                                            (unsigned long)dataLen, info->tmpFileName, (int)writeRet);
                return -1;
            }
            md5_update(&info->md5, data, dataLen);
        }
        if ( !data ) {
            /*
             * We are at EOF.  Close the output file and re-open it for reading.
             * Compute the digests too.
             */
            bpc_fileZIO_close(&info->fd);
            if ( bpc_fileZIO_open(&info->fd, info->tmpFileName, 0, info->compress) ) {
                info->errorCnt++;
                bpc_logErrf("bpc_poolWrite_write: can't open %s for reading", info->tmpFileName);
                return -1;
            }
            info->fdOpen = 1;
            md5_result(&info->md5, info->digest.digest);
            info->digest.len = MD5_DIGEST_LEN;
            if ( BPC_PoolV3Enabled ) {
                bpc_digest_buffer2MD5_v3(&info->digest_v3, info->buffer, info->fileSize);
                if ( BPC_LogLevel >= 8 ) {
                    char hexStr_v3[BPC_DIGEST_LEN_MAX * 2 + 1], hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];
                    bpc_digest_digest2str(&info->digest,    hexStr);
                    bpc_digest_digest2str(&info->digest_v3, hexStr_v3);
                    bpc_logMsgf("bpc_poolWrite_write: digest is %s, v3 is %s\n", hexStr, hexStr_v3);
                }
            } else if ( BPC_LogLevel >= 8 ) {
                char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];
                bpc_digest_digest2str(&info->digest, hexStr);
                bpc_logMsgf("bpc_poolWrite_write: digest is %s\n", hexStr);
            }
            info->state = 2;
        }
    }
    if ( info->state == 2 ) {
        uint32 ext = 0;
        char poolPath[BPC_MAXPATHLEN];
        STRUCT_STAT st;

        /*
         * In this state we have either the full file in info->buffer, or the full file
         * is opened for reading with info->fd.  We also have digests computed.
         *
         * We figure out the list of candidate files to match.  If there are any
         * new digest files then we just try to match them.  Otherwise we also
         * try to match any old V3 files.
         */
        info->digestExtZeroLen = -1;
        while ( 1 ) {
            char poolPath[BPC_MAXPATHLEN];

            bpc_digest_append_ext(&info->digest, ext);
            bpc_digest_md52path(poolPath, info->compress, &info->digest);
            /*
             * For >= V4.x pool, don't attempt to match pool files that
             * are empty, since in >= V4.x we don't rename pool
             * files in a repeated chain and instead replace them
             * with an empty file.
             * If the candidate has the other execute bit set, we do a safe
             * reset of the bit and allow matches to occur.  This is used to flag
             * pool files that will be deleted next time BackupPC_refCountUpdate
             * runs, so resetting that bit prevents the deletion.
             */
            if ( stat(poolPath, &st) ) break;
            if ( S_ISREG(st.st_mode) ) {
                if ( st.st_size > 0 ) {
                    bpc_candidate_file *candidateFile;
                    if ( (st.st_mode & S_IXOTH) && bpc_poolWrite_unmarkPendingDelete(poolPath) ) {
                        if ( BPC_LogLevel >= 7 ) bpc_logMsgf("Couldn't unmark candidate matching file %s (skipped)\n", poolPath);
                        break;
                    }
                    candidateFile = malloc(sizeof(bpc_candidate_file));
                    if ( !candidateFile ) {
                        info->errorCnt++;
                        bpc_logErrf("bpc_poolWrite_write: can't allocate bpc_candidate_file\n");
                        return -1;
                    }
                    candidateFile->digest   = info->digest;
                    candidateFile->fileSize = st.st_size;
                    candidateFile->v3File   = 0;
                    strcpy(candidateFile->fileName, poolPath);
                    candidateFile->next = info->candidateList;
                    info->candidateList = candidateFile;
                    if ( BPC_LogLevel >= 7 ) bpc_logMsgf("Candidate matching file %s\n", candidateFile->fileName);
                } else if ( info->digestExtZeroLen < 0 ) {
                    /*
                     * Remember the first empty file in case we have to insert a
                     * new pool file here.
                     */
                    info->digestExtZeroLen = ext;
                }
            }
            ext++;
        }
        /*
         * Remember the next open slot in case we have to add a new pool
         * file here.
         */
        info->digestExtOpen = ext;
        bpc_digest_append_ext(&info->digest, 0);

        if ( BPC_PoolV3Enabled && !info->candidateList ) {
            /*
             * No matching candidate files so far, so now look in V3 pool
             */
            ext = 0;
            while ( 1 ) {
                bpc_digest_append_ext(&info->digest_v3, ext);
                bpc_digest_md52path_v3(poolPath, info->compress, &info->digest_v3);
                ext++;

                /*
                 * For V3.x pool, don't attempt to match pool files:
                 *  - that already have too many hardlinks.
                 *  - with only one link since starting in BackupPC v3.0,
                 *    BackupPC_nightly could be running in parallel (and
                 *    removing those files).  This doesn't eliminate all
                 *    possible race conditions, but just reduces the
                 *    odds.  Other design steps eliminate the remaining
                 *    race conditions of linking vs removing.
                 */
                if ( stat(poolPath, &st) ) break;
                if ( S_ISREG(st.st_mode)
                        && 1 < st.st_nlink && st.st_nlink < (unsigned)BPC_HardLinkMax ) {
                    bpc_candidate_file *candidateFile = malloc(sizeof(bpc_candidate_file));
                    if ( !candidateFile ) {
                        info->errorCnt++;
                        bpc_logErrf("bpc_poolWrite_write: can't allocate bpc_candidate_file\n");
                        return -1;
                    }
                    candidateFile->digest   = info->digest_v3;
                    candidateFile->fileSize = st.st_size;
                    candidateFile->v3File   = 1;
                    strcpy(candidateFile->fileName, poolPath);
                    candidateFile->next = info->candidateList;
                    info->candidateList = candidateFile;
                    if ( BPC_LogLevel >= 7 ) bpc_logMsgf("Candidate v3 matching file %s\n", candidateFile->fileName);
                }
            }
            bpc_digest_append_ext(&info->digest_v3, 0);
        }
        /*
         * Open the first set of candidate files.
         */
        bpc_poolWrite_updateMatches(info); 
        info->state = 3;
    }
    if ( info->state == 3 ) {
        /*
         * In this state we are continuing to match against candidate files
        */
        while ( 1 ) {
            int i, replaceCnt = 0, nMatch = 0;
            uchar *buf0 = TempBuf;
            uchar *buf1 = TempBuf + COMPARE_BUF_SZ;
            uchar *buf;
            OFF_T nread0;

            if ( info->fdOpen ) {
                nread0 = bpc_fileZIO_read(&info->fd, buf0, COMPARE_BUF_SZ);
                buf = buf0;
            } else {
                nread0 = COMPARE_BUF_SZ;
                if ( nread0 > info->bufferIdx - info->matchPosn ) nread0 = info->bufferIdx - info->matchPosn;
                buf = info->buffer + info->matchPosn;
            }
            for ( i = 0 ; i < BPC_POOL_WRITE_CONCURRENT_MATCH ; i++ ) {
                OFF_T nread1;

                if ( !info->match[i].used ) continue;
                nMatch++;
                /*
                 * Try to read an extra byte when we expect EOF, to make sure the candidate file is also at EOF
                 */
                nread1 = bpc_fileZIO_read(&info->match[i].fd, buf1, nread0 > 0 ? nread0 : 1);
                if ( BPC_LogLevel >= 9 ) bpc_logMsgf("Read %d bytes of %d from match[%d] (%s)\n", (int)nread1, (int)nread0, i, info->match[i].fileName);
                if ( nread0 != nread1 || (nread0 > 0 && memcmp(buf, buf1, nread0)) ) {
                    bpc_fileZIO_close(&info->match[i].fd);
                    if ( BPC_LogLevel >= 8 ) bpc_logMsgf("match[%d] no longer matches\n", i);
                    info->match[i].used = 0;
                    replaceCnt++;
                }
            }
            info->matchPosn += nread0;

            if ( replaceCnt ) {
                nMatch = bpc_poolWrite_updateMatches(info); 
            }
            if ( nread0 == 0 || nMatch == 0 ) {
                /* 
                 * we are at eof (with a match) or there are no matches
                 */
                info->state = 4;
                break;
            }
        }
    }
    if ( info->state == 4 ) {
        /*
         * see if there is a matching file
         */
        int i, nMatch = 0, iMatch = 0;

        for ( i = BPC_POOL_WRITE_CONCURRENT_MATCH -1 ; i >= 0 ; i-- ) {
            if ( !info->match[i].used ) continue;
            nMatch++;
            iMatch = i;
        }
        if ( nMatch == 0 ) {
            ssize_t writeRet;
            /*
             * Need to write a new file if not written already
             */
            if ( !info->fdOpen && info->fileSize > 0 ) {
                if ( bpc_fileZIO_open(&info->fd, info->tmpFileName, 1, info->compress) ) {
                    info->errorCnt++;
                    bpc_logErrf("bpc_poolWrite_write: can't open/create %s for writing", info->tmpFileName);
                    return -1;
                }
                if ( info->bufferIdx > 0 ) {
                    if ( (writeRet = bpc_fileZIO_write(&info->fd, info->buffer, info->bufferIdx)) != (ssize_t)info->bufferIdx ) {
                        info->errorCnt++;
                        bpc_logErrf("bpc_poolWrite_write: write of %u bytes to %s failed, return = %d",
                                                    info->bufferIdx, info->tmpFileName, (int)writeRet);
                        return -1;
                    }
                }
                bpc_fileZIO_close(&info->fd);
            }
            if ( info->fileSize > 0 ) {
                char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];
                bpc_digest_append_ext(&info->digest, 0);
                bpc_digest_digest2str(&info->digest, hexStr);
                if ( BPC_LogLevel >= 5 ) bpc_logMsgf("No match... adding %s to pool (digest = %s)\n", info->tmpFileName, hexStr);
                bpc_poolWrite_addToPool(info, info->tmpFileName, 0);
            } else {
                if ( BPC_LogLevel >= 5 ) bpc_logMsgf("Zero length file - don't match anything\n");
                info->digest.len   = 0;
                info->retValue     = 1;
                info->poolFileSize = 0;
            }
        } else {
            /*
             * We matched a pool file
             */
            if ( nMatch > 1 ) {
                char hexStr[BPC_DIGEST_LEN_MAX * 2 + 1];
                if ( BPC_LogLevel >= 4 ) bpc_logMsgf("Botch - got multiple pool file matches\n");
                info->errorCnt++;
                bpc_digest_digest2str(&info->digest, hexStr);
                bpc_logErrf("bpc_poolWrite_write: got %d matching files for digest %s\n", nMatch, hexStr);
            }
            if ( BPC_LogLevel >= 7 ) bpc_logMsgf("Found match with match[%d] (%s)\n", iMatch, info->match[iMatch].fileName);
            if ( info->match[iMatch].v3File ) {
                bpc_digest_append_ext(&info->digest, 0);
                bpc_poolWrite_addToPool(info, info->match[iMatch].fileName, info->match[iMatch].v3File);
            } else {
                info->digest       = info->match[iMatch].digest;
                info->retValue     = 1;
                info->poolFileSize = info->match[iMatch].fileSize;
            }
            if ( info->fdOpen ) {
                bpc_fileZIO_close(&info->fd);
                unlink(info->tmpFileName);
                info->fdOpen = 0;
            }
        }
    }
    return 0;
}

int bpc_poolWrite_createPoolDir(bpc_poolWrite_info *info, bpc_digest *digest)
{
    char path[BPC_MAXPATHLEN], *p;
    int ret;

    /*
     * get the full path, and prune off the file name to get the directory
     */
    bpc_digest_md52path(path, info->compress, digest);
    if ( !(p = strrchr(path, '/')) ) {
        info->errorCnt++;
        bpc_logErrf("bpc_poolWrite_createPoolDir: can't find trailing / in path %s", path);
        return -1;
    }
    *p = '\0';

    if ( (ret = bpc_path_create(path)) ) {
        info->errorCnt++;
        bpc_logErrf("bpc_poolWrite_createPoolDir: can't create directory path %s", path);
    }
    return ret;
}

void bpc_poolWrite_cleanup(bpc_poolWrite_info *info)
{
    int i;

    if ( info->fdOpen ) bpc_fileZIO_close(&info->fd);
    info->fdOpen = 0;

    while ( info->candidateList ) {
        bpc_candidate_file *candidateFile = info->candidateList;
        info->candidateList = candidateFile->next;
        free(candidateFile);
    }
    for ( i = 0 ; i < BPC_POOL_WRITE_CONCURRENT_MATCH ; i++ ) {
        if ( !info->match[i].used ) continue;
        bpc_fileZIO_close(&info->match[i].fd);
        info->match[i].used = 0;
    }
    if ( info->buffer ) {
        free(info->buffer);
        info->buffer = NULL;
    }
}

/*
 * Called after the data is written.  The return information is passed via four arguments:
 *
 *      (match, digest, poolFileSize, errorCnt)
 *
 * The return values are:
 *
 *    - match:
 *        If match == 0, then the file doesn't match either the new or old pools.
 *        The file has been added to the pool.
 *
 *        If match == 1, then the file matches the new pool.  No file is
 *        written.
 *
 *        If match == 2, then the file matches the old pool.  The old pool
 *        file was moved to become the new pool file.
 *
 *    - digest: the 16+ byte binary MD5 digest, possibly appended with
 *      on or more additional bytes to point to the right pool file in
 *      case there are MD5 collisions
 *
 *    - poolFileSize: the compressed pool file size
 *
 *    - errorCnt: number of errors
 */
void bpc_poolWrite_close(bpc_poolWrite_info *info, int *match, bpc_digest *digest, OFF_T *poolFileSize, int *errorCnt)
{
    bpc_poolWrite_write(info, NULL, 0);
    bpc_poolWrite_cleanup(info);
    *match        = info->retValue;
    *digest       = info->digest;
    *poolFileSize = info->poolFileSize;
    *errorCnt     = info->errorCnt;
}

void bpc_poolWrite_repeatPoolWrite(bpc_poolWrite_info *info, char *fileNameTmp)
{
    bpc_poolWrite_cleanup(info);

    if ( BPC_LogLevel >= 5 ) bpc_logMsgf("bpc_poolWrite_repeatPoolWrite: rewriting %s\n", fileNameTmp);
    if ( info->retryCnt++ > 8 ) {
        bpc_logErrf("bpc_poolWrite_repeatPoolWrite: giving up on %s after %d attempts\n", fileNameTmp, info->retryCnt);
        info->errorCnt++;
        unlink(fileNameTmp);
        return;
    }
    strcpy(info->tmpFileName, fileNameTmp);
    if ( bpc_fileZIO_open(&info->fd, fileNameTmp, 0, info->compress) < 0 ) {
        bpc_logErrf("bpc_poolWrite_repeatPoolWrite: can't open %s for reading", fileNameTmp);
        info->errorCnt++;
        return;
    }
    info->eof    = 1;
    info->state  = 2;
    info->fdOpen = 1;
    bpc_poolWrite_write(info, NULL, 0);
}

int bpc_poolWrite_copyToPool(bpc_poolWrite_info *info, char *poolPath, char *fileName)
{
    int fdRead, fdWrite;
    int nRead, nWrite;

    if ( (fdWrite = open(poolPath, O_WRONLY | O_CREAT | O_EXCL, 0666)) < 0 ) {
        info->errorCnt++;
        bpc_logErrf("bpc_poolWrite_copyToPool: can't open/create %s for writing", poolPath);
        return -1;
    }
    if ( (fdRead = open(fileName, O_RDONLY)) < 0 ) {
        info->errorCnt++;
        bpc_logErrf("bpc_poolWrite_copyToPool: can't open %s for reading", fileName);
        return -1;
    }

    while ( (nRead = read(fdRead, (char*)TempBuf, BPC_POOL_WRITE_BUF_SZ)) > 0 ) {
        char *p = (char*)TempBuf;
        int thisWrite;

        nWrite  = 0;
        while ( nWrite < nRead ) {
            do {
                thisWrite = write(fdWrite, p, nRead - nWrite);
            } while ( thisWrite < 0 && errno == EINTR );
            if ( thisWrite < 0 ) {
                info->errorCnt++;
                bpc_logErrf("bpc_poolWrite_copyToPool: write to %s failed (errno = %d)", poolPath, errno);
                close(fdWrite);
                close(fdRead);
                unlink(poolPath);
                return -1;
            }
            p      += thisWrite;
            nWrite += thisWrite;
        }
    }
    close(fdWrite);
    close(fdRead);
    return 0;
}

void bpc_poolWrite_addToPool(bpc_poolWrite_info *info, char *fileName, int v3PoolFile)
{
    STRUCT_STAT st;
    char poolPath[BPC_MAXPATHLEN];
    int redo = 0;

    if ( bpc_poolWrite_createPoolDir(info, &info->digest) ) return;

    /*
     * If originally present, make sure the zero-length file is still there (and still
     * zero-length), and the open slot is still open.  If not, it probably means someone
     * beat us to it, and we should re-do the whole pool matching to see if the newly
     * added pool file now matches.
     */
    if ( info->digestExtZeroLen >= 0 ) {
        bpc_digest_append_ext(&info->digest, info->digestExtZeroLen);
        bpc_digest_md52path(poolPath, info->compress, &info->digest);
        if ( stat(poolPath, &st) || st.st_size != 0 ) {
            redo = 1;
        }
    }
    if ( !redo ) {
        bpc_digest_append_ext(&info->digest, info->digestExtOpen);
        bpc_digest_md52path(poolPath, info->compress, &info->digest);
        if ( !stat(poolPath, &st) ) {
            redo = 1;
        }
    }

    /*
     * Try to insert the new file at the zero-length file slot (if present).
     */
    if ( !redo && info->digestExtZeroLen >= 0 ) {
        char lockFile[BPC_MAXPATHLEN];
        int lockFd;
        /*
         * We can replace a zero-length file, but only via locking to
         * avoid race conditions.  Since the hardlinking code below doesn't
         * use a lock, we can't remove the file and use a hardlink
         * because of race conditions - another process might be
         * inserting with the same digest and grab the slot.
         *
         * So we make sure we have exclusive access via a lock file,
         * check that the file is still zero-length, and then rename
         * the file.  If that fails then we redo everything.
         */
        bpc_digest_append_ext(&info->digest, info->digestExtZeroLen);
        bpc_digest_md52path(poolPath, info->compress, &info->digest);
        if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_poolWrite_addToPool: replacing empty pool file %s with %s\n", poolPath, fileName);
        snprintf(lockFile, BPC_MAXPATHLEN, "%s.lock", poolPath);
        lockFd = bpc_lockRangeFile(lockFile, 0, 1, 1);
        /*
         * If we don't have the lock, or the file is no longer zero length, or the rename fails,
         * then try again.
         */
        if ( lockFd < 0 || stat(poolPath, &st) || st.st_size != 0 || rename(fileName, poolPath) ) {
            if ( BPC_LogLevel >= 5 ) {
                bpc_logMsgf("bpc_poolWrite_addToPool: lock/rename failed: need to repeat write (lockFd = %d, size = %lu, errno = %d)\n",
                             lockFd, (unsigned long)st.st_size, errno);
            }
            if ( lockFd >= 0 ) {
                bpc_unlockRangeFile(lockFd);
            }
            unlink(lockFile);
            redo = 1;
        } else {
            chmod(poolPath, 0444);
            stat(poolPath, &st);
            info->retValue     = v3PoolFile ? 2 : 0;
            info->poolFileSize = st.st_size;
            bpc_unlockRangeFile(lockFd);
            unlink(lockFile);
            return;
        }
    }

    /*
     * Now try to link the file to the new empty slot at the end
     */
    if ( !redo ) {
        int linkOk, statOk;
        ino_t fileIno, poolIno;
        /*
         * Since this is a new slot, there is no need to do locking since
         * the link or open operations below are atomic/exclusive.
         *
         * First try to hardlink to the empty pool file slot
         */
        bpc_digest_append_ext(&info->digest, info->digestExtOpen);
        bpc_digest_md52path(poolPath, info->compress, &info->digest);
        if ( stat(fileName, &st) ) {
            info->errorCnt++;
            bpc_logErrf("bpc_poolWrite_addToPool: can't stat %s\n", fileName);
            return;
        }
        fileIno = st.st_ino;
        linkOk = !link(fileName, poolPath);
        if ( !(statOk = !stat(poolPath, &st)) ) linkOk = 0;
        poolIno = st.st_ino;
        if ( BPC_LogLevel >= 6 ) bpc_logMsgf("bpc_poolWrite_addToPool: link %s -> %s (linkOk = %d, statOk = %d, ino = %lu/%lu)\n",
                                                poolPath, fileName, linkOk, statOk, (unsigned long)fileIno, (unsigned long)poolIno);

        /*
         * make sure the link really worked by checking inode numbers
         * TODO: test these different cases.
         */
        if ( statOk && fileIno == poolIno ) {
            /*
             * remove the original file and return
             */
            unlink(fileName);
            chmod(poolPath, 0444);
            info->retValue     = v3PoolFile ? 2 : 0;
            info->poolFileSize = st.st_size;
            return;
        }
        /*
         * Something failed.  If the stat failed, the hardlink failure wasn't due
         * to another file being added by someone else.  Perhaps the cpool is
         * split across multiple file systems?
         */
        if ( !statOk ) {
            /*
             * The hardlink failed.  This could be due to hitting the hardlink
             * limit, or the fact that fileName and poolPath are on different
             * file systems, or the fileName didn't get writting.
             * Just copy the file instead (assuming fileName got written).
             */
            bpc_poolWrite_copyToPool(info, poolPath, fileName);
            return;
        }
    }

    /*
     * We need to redo the pool write, since it appears someone else has added
     * a pool file with the same digest.
     */
    bpc_poolWrite_repeatPoolWrite(info, fileName);
}

/*
 * Safely remove the o+x permission that marks a file for future deletion.
 * Similar locking is done by BackupPC_refCountUpdate so we can avoid any
 * race conditions with the file actually being deleted.
 *
 * Returns 0 on success.
 */
int bpc_poolWrite_unmarkPendingDelete(char *poolPath)
{
    char lockFile[BPC_MAXPATHLEN], *p;
    STRUCT_STAT st;
    int lockFd;

    /*
     * The lock file is in the first level of pool sub directories - one level
     * up from the full path.  So we need to find the 2nd last '/'.
     */
    snprintf(lockFile, BPC_MAXPATHLEN, "%s", poolPath);
    if ( !(p = strrchr(lockFile, '/')) ) return -1;
    *p = '\0';
    if ( !(p = strrchr(lockFile, '/')) ) return -1;
    snprintf(p + 1, BPC_MAXPATHLEN - (p + 1 - lockFile), "%s", "LOCK");
    if ( (lockFd = bpc_lockRangeFile(lockFile, 0, 1, 1)) < 0 ) return -1;
    if ( !stat(poolPath, &st) && !chmod(poolPath, st.st_mode & ~S_IXOTH) ) {
        if ( BPC_LogLevel >= 7 ) bpc_logMsgf("bpc_poolWrite_unmarkPendingDelete(%s) succeeded\n", poolPath);
        bpc_unlockRangeFile(lockFd);
        return 0;
    } else {
        if ( BPC_LogLevel >= 7 ) bpc_logMsgf("bpc_poolWrite_unmarkPendingDelete(%s) failed\n", poolPath);
        bpc_unlockRangeFile(lockFd);
        return -1;
    }
}
