/*
 * Routines for reading and writing compressed files using zlib
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
 * Open a regular or compressed file for reading or writing/create
 */
int bpc_fileZIO_open(bpc_fileZIO_fd *fd, char *fileName, int writeFile, int compressLevel)
{
    fd->strm.next_out  = NULL;
    fd->strm.zalloc    = NULL;
    fd->strm.zfree     = NULL;
    fd->strm.opaque    = NULL;

    fd->compressLevel  = compressLevel;
    fd->first          = 1;
    fd->write          = writeFile;
    fd->eof            = 0;
    fd->error          = 0;
    fd->writeTeeStderr = 0;

    fd->lineBuf        = NULL;
    fd->lineBufSize    = 0;
    fd->lineBufLen     = 0;
    fd->lineBufIdx     = 0;
    fd->lineBufEof     = 0;

    fd->bufSize = 1 << 20;       /* 1MB */
    if ( !(fd->buf = malloc(fd->bufSize)) ) {
        bpc_logErrf("bpc_fileZIO_open: can't allocate %u bytes\n", (unsigned)fd->bufSize);
        return -1;
    }

    if ( writeFile ) {
        fd->fd = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0660);
        if ( fd->fd < 0 ) {
            /*
             * try removing first
             */
            unlink(fileName);
            fd->fd = open(fileName, O_WRONLY | O_CREAT | O_TRUNC, 0660);
        }
        if ( fd->fd < 0 ) return -1;
        if ( fd->compressLevel ) {
            if (deflateInit2(&fd->strm, compressLevel, Z_DEFLATED, MAX_WBITS, 8,
                                         Z_DEFAULT_STRATEGY) != Z_OK) {
                bpc_logErrf("bpc_fileZIO_open: compression init failed\n");
                return -1;
            }
            fd->strm.next_out  = (Bytef*)fd->buf;
            fd->strm.avail_out = fd->bufSize;
        }
    } else {
        fd->fd = open(fileName, O_RDONLY);
        if ( fd->fd < 0 ) return -1;
        if ( fd->compressLevel ) {
            if ( inflateInit(&fd->strm) != Z_OK ) {
                bpc_logErrf("bpc_fileZIO_open: compression init failed\n");
                return -1;
            }
            fd->strm.avail_in = 0;
        }
    }
    if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_fileZIO_open(%s, %d, %d) -> %d\n", fileName, writeFile, compressLevel, fd->fd);
    return 0;
}

/*
 * Open an existing FILE stream for reading/writing.
 * Note: we used unbuffered integer fds here, and we simply grab the underlying integer fd.  That will
 * mess up the FILE stream buffering if anything has been read/written from/to the FILE.
 *
 * This function is only used to support the legacy BackupPC::FileZIO feature that allows you to
 * pass STDIN in as an argument to open().
 */
int bpc_fileZIO_fdopen(bpc_fileZIO_fd *fd, FILE *stream, int writeFile, int compressLevel)
{
    fd->strm.next_out  = NULL;
    fd->strm.zalloc    = NULL;
    fd->strm.zfree     = NULL;
    fd->strm.opaque    = NULL;

    fd->compressLevel  = compressLevel;
    fd->first          = 1;
    fd->write          = writeFile;
    fd->eof            = 0;
    fd->error          = 0;
    fd->writeTeeStderr = 0;

    fd->lineBuf        = NULL;
    fd->lineBufSize    = 0;
    fd->lineBufLen     = 0;
    fd->lineBufIdx     = 0;
    fd->lineBufEof     = 0;

    fd->fd = fileno(stream);
    if ( fd->fd < 0 ) return -1;

    fd->bufSize = 1 << 20;       /* 1MB */
    if ( !(fd->buf = malloc(fd->bufSize)) ) {
        bpc_logErrf("bpc_fileZIO_fdopen: can't allocate %u bytes\n", (unsigned)fd->bufSize);
        return -1;
    }

    if ( fd->compressLevel ) {
        if ( writeFile ) {
            if (deflateInit2(&fd->strm, compressLevel, Z_DEFLATED, MAX_WBITS, 8,
                                         Z_DEFAULT_STRATEGY) != Z_OK) {
                bpc_logErrf("bpc_fileZIO_open: compression init failed\n");
                return -1;
            }
            fd->strm.next_out  = (Bytef*)fd->buf;
            fd->strm.avail_out = fd->bufSize;
        } else {
            if ( inflateInit(&fd->strm) != Z_OK ) {
                bpc_logErrf("bpc_fileZIO_open: compression init failed\n");
                return -1;
            }
            fd->strm.avail_in = 0;
        }
    }
    if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_fileZIO_fdopen(%d, %d) -> %d\n", writeFile, compressLevel, fd->fd);
    return 0;
}

void bpc_fileZIO_writeTeeStderr(bpc_fileZIO_fd *fd, int tee)
{
    fd->writeTeeStderr = tee;
}

/*
 * Read from a compressed or regular file.
 */
ssize_t bpc_fileZIO_read(bpc_fileZIO_fd *fd, uchar *buf, size_t nRead)
{
    size_t totalRead = 0;

    if ( fd->write || fd->fd < 0 ) return -1;
    if ( fd->compressLevel == 0 ) {
        ssize_t thisRead;
        while ( nRead > 0 ) {
            do {
                thisRead = read(fd->fd, buf, nRead);
            } while ( thisRead < 0 && errno == EINTR );
            if ( thisRead < 0 ) return thisRead;
            if ( thisRead == 0 ) return totalRead;
            buf       += thisRead;
            nRead     -= thisRead;
            totalRead += thisRead;
        }
        return totalRead;
    }
    if ( fd->error ) return fd->error;
    while ( nRead > 0 ) {
        /*
         * Start by trying to read more of the compressed input file
         */
        int maxRead, thisRead = -1;

        if ( fd->strm.avail_in == 0 ) {
            fd->strm.next_in = (Bytef*)fd->buf;
        }
        maxRead = fd->bufSize - ((fd->strm.next_in - (Bytef*)fd->buf) + fd->strm.avail_in);

        if ( !fd->eof && maxRead > 0 ) {
            do {
                thisRead = read(fd->fd, fd->strm.next_in + fd->strm.avail_in, maxRead);
            } while ( thisRead < 0 && errno == EINTR );
            if ( thisRead < 0 ) {
                fd->error = thisRead;
                return fd->error;
            }
            fd->strm.avail_in += thisRead;
            if ( thisRead == 0 ) {
                fd->eof = 1;
            }
        }

        while ( nRead > 0 ) {
            int status, numOut;

            fd->strm.next_out  = (Bytef*)buf;
            fd->strm.avail_out = nRead;

            if ( fd->first && fd->strm.avail_in > 0 ) {
                /*
                 * we are at the very start of a new zlib block (or it could be chached checksums)
                 */
                fd->first = 0;
                if ( fd->strm.next_in[0] == 0xd6 || fd->strm.next_in[0] == 0xd7 ) {
                    /*
                     * Flag 0xd6 or 0xd7 means this is a compressed file with
                     * appended md4 block checksums for rsync.  Change
                     * the first byte back to 0x78 and proceed.
                     */
                    fd->strm.next_in[0] = 0x78;
                } else if ( fd->strm.next_in[0] == 0xb3 ) {
                    /*
                     * Flag 0xb3 means this is the start of the rsync
                     * block checksums, so consider this as EOF for
                     * the compressed file.  Also seek the file so
                     * it is positioned at the 0xb3.
                     */
                    fd->eof = 1;
                    /* TODO: check return status */
                    lseek(fd->fd, -fd->strm.avail_in, SEEK_CUR);
                    fd->strm.avail_in = 0;
                }
            }
            status    = inflate(&fd->strm, fd->eof ? Z_SYNC_FLUSH : Z_NO_FLUSH);
            numOut    = fd->strm.next_out - (Bytef*)buf;
            nRead     -= numOut;
            buf       += numOut;
            totalRead += numOut;

            if ( BPC_LogLevel >= 10 ) bpc_logMsgf("inflate returns %d; thisRead = %d, avail_in = %d, numOut = %d\n", status, thisRead, fd->strm.avail_in, numOut);

            if ( fd->eof && fd->strm.avail_in == 0 && numOut == 0 ) return totalRead;
            if ( status == Z_OK && fd->strm.avail_in == 0 ) break;
            if ( status == Z_BUF_ERROR && fd->strm.avail_in == 0 && numOut == 0 ) break;
            if ( status == Z_STREAM_END ) {
                inflateReset(&fd->strm);
                fd->first = 1;
            }
            if ( status < 0 ) return status;
        }
    }
    return totalRead;
}

/*
 * Write to a compressed or regular file.
 * Write flush and eof is indicated with nWrite == 0.
 */
ssize_t bpc_fileZIO_write(bpc_fileZIO_fd *fd, uchar *buf, size_t nWrite)
{
    if ( !fd->write || fd->fd < 0 ) return -1;
    if ( fd->eof ) return 0;
    if ( fd->writeTeeStderr ) (void)fwrite((char*)buf, nWrite, 1, stderr);
    if ( fd->compressLevel == 0 ) {
        int thisWrite, totalWrite = 0;
        while ( nWrite > 0 ) {
            do {
                thisWrite = write(fd->fd, buf, nWrite);
            } while ( thisWrite < 0 && errno == EINTR );
            if ( thisWrite < 0 ) return thisWrite;
            buf        += thisWrite;
            nWrite     -= thisWrite;
            totalWrite += thisWrite;
        }
        return totalWrite;
    }
    if ( fd->error ) return fd->error;

    if ( nWrite == 0 || (fd->strm.total_in > (1 << 23) && fd->strm.total_out < (1 << 18)) ) {
        /* 
         * final or intermediate flush (if the compression ratio is too high, since the
         * perl Compress::Zlib implementation allocates the output buffer for inflate
         * and it could grow to be very large).
         */
        if ( BPC_LogLevel >= 10 ) bpc_logMsgf("Flushing (nWrite = %d)\n", nWrite);
        while ( 1 ) {
            int status, numOut, thisWrite;
            
            fd->strm.next_in   = NULL;
            fd->strm.avail_in  = 0;
            fd->strm.next_out  = (Bytef*)fd->buf;
            fd->strm.avail_out = fd->bufSize;
            status = deflate(&fd->strm, Z_FINISH);
            numOut = fd->strm.next_out - (Bytef*)fd->buf;

            while ( numOut > 0 ) {
                do {
                    thisWrite = write(fd->fd, fd->buf, numOut);
                } while ( thisWrite < 0 && errno == EINTR );
                if ( thisWrite < 0 ) return thisWrite;
                numOut -= thisWrite;
            }
            if ( status != Z_OK ) break;
        }
        deflateReset(&fd->strm);
    }
    if ( nWrite == 0 ) {
        fd->eof = 1;
        return nWrite;
    }

    fd->strm.next_in  = (Bytef*)buf;
    fd->strm.avail_in = nWrite;
    while ( fd->strm.avail_in > 0 ) {
        int numOut, thisWrite;

        fd->strm.next_out  = (Bytef*)fd->buf;
        fd->strm.avail_out = fd->bufSize;
        deflate(&fd->strm, Z_NO_FLUSH);
        numOut = fd->strm.next_out - (Bytef*)fd->buf;

        while ( numOut > 0 ) {
            do {
                thisWrite = write(fd->fd, fd->buf, numOut);
            } while ( thisWrite < 0 && errno == EINTR );
            if ( thisWrite < 0 ) return thisWrite;
            numOut -= thisWrite;
        }
    }
    return nWrite;
}

int bpc_fileZIO_close(bpc_fileZIO_fd *fd)
{
    if ( fd->fd < 0 ) return -1;

    if ( fd->compressLevel ) {
        if ( fd->write ) {
            /*
             * Flush the output file
             */
            bpc_fileZIO_write(fd, NULL, 0);
            deflateEnd(&fd->strm);
        } else {
            inflateEnd(&fd->strm);
        }
    }
    if ( BPC_LogLevel >= 8 ) bpc_logMsgf("bpc_fileZIO_close(%d)\n", fd->fd);
    close(fd->fd);
    if ( fd->lineBuf ) free(fd->lineBuf);
    fd->lineBuf = NULL;
    if ( fd->buf ) free(fd->buf);
    fd->buf = NULL;
    fd->fd = -1;
    return 0;
}

int bpc_fileZIO_rewind(bpc_fileZIO_fd *fd)
{
    if ( fd->write ) return -1;

    if ( fd->compressLevel ) {
        inflateReset(&fd->strm);
        fd->first         = 1;
        fd->eof           = 0;
        fd->error         = 0;
        fd->strm.avail_in = 0;
    }
    return lseek(fd->fd, 0, SEEK_SET) == 0 ? 0 : -1;
}

/*
 * Returns \n terminated lines, one at a time, from the opened read stream.
 * The returned string is not '\0' terminated.  At EOF sets *str = NULL;
 */
int bpc_fileZIO_readLine(bpc_fileZIO_fd *fd, char **str, size_t *strLen)
{
    if ( !fd->lineBuf ) {
        /*
         * allocate initial read buffer
         */
        fd->lineBufSize = 65536;
        if ( !(fd->lineBuf = malloc(fd->lineBufSize)) ) {
            bpc_logErrf("bpc_fileZIO_readLine: can't allocate %u bytes\n", (unsigned)fd->lineBufSize);
            return -1;
        }
        fd->lineBufLen = 0;
        fd->lineBufIdx = 0;
        fd->lineBufEof = 0;
    }
    while ( 1 ) {
        char *p;

        if ( fd->lineBufIdx < fd->lineBufLen ) {
            if ( (p = memchr(fd->lineBuf + fd->lineBufIdx, '\n', fd->lineBufLen - fd->lineBufIdx)) ) {
                /*
                 * found next complete line
                 */
                p++;
                *str    = fd->lineBuf + fd->lineBufIdx;
                *strLen = p - (fd->lineBuf + fd->lineBufIdx);
                fd->lineBufIdx += p - (fd->lineBuf + fd->lineBufIdx);
                return 0;
            } else if ( fd->lineBufEof ) {
                /*
                 * return last string - not \n terminated
                 */
                *str    = fd->lineBuf + fd->lineBufIdx;
                *strLen = fd->lineBufLen - fd->lineBufIdx;
                fd->lineBufIdx += fd->lineBufLen - fd->lineBufIdx;
                return 0;
            } else if ( fd->lineBufLen >= fd->lineBufSize ) {
                /*
                 * No complete lines left, and buffer is full.  Either move the unused buffer down to make
                 * more room for reading, or make the buffer bigger.
                 */
                if ( fd->lineBufIdx > 0 ) {
                    memmove(fd->lineBuf, fd->lineBuf + fd->lineBufIdx, fd->lineBufLen - fd->lineBufIdx);
                    fd->lineBufLen -= fd->lineBufIdx;
                    fd->lineBufIdx  = 0;
                } else {
                    fd->lineBufSize *= 2;
                    if ( !(fd->lineBuf = realloc(fd->lineBuf, fd->lineBufSize)) ) {
                        bpc_logErrf("bpc_fileZIO_readLine: can't reallocate %u bytes\n", (unsigned)fd->lineBufSize);
                        return -1;
                    }
                }
            }
        }
        if ( fd->lineBufIdx >= fd->lineBufLen && fd->lineBufEof ) {
            /*
             * at EOF
             */
            *str    = NULL;
            *strLen = 0;
            return 0;
        }
        if ( fd->lineBufIdx >= fd->lineBufLen ) {
            fd->lineBufLen = 0;
            fd->lineBufIdx = 0;
        }
        if ( fd->lineBufLen < fd->lineBufSize && !fd->lineBufEof ) {
            int nread = bpc_fileZIO_read(fd, (uchar*)fd->lineBuf + fd->lineBufLen, fd->lineBufSize - fd->lineBufLen);
            if ( nread < 0 ) {
                bpc_logErrf("bpc_fileZIO_readLine: reading %u returned %d\n", (unsigned)(fd->lineBufSize - fd->lineBufLen), nread);
                return nread;
            }
            if ( nread == 0 ) fd->lineBufEof = 1;
            fd->lineBufLen += nread;
        }
    }
}
