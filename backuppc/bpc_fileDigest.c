/*
 * Library routines
 *
 * Copyright (C) 2020 Craig Barratt.
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
 * Compute the md5 digest of a file. Returns 0 on success
 */
int bpc_fileDigest(char *fileName, int compress, bpc_digest *digest)
{
    md_context md5;
    bpc_fileZIO_fd fd;
    ssize_t nRead;
    uchar buffer[1 << 20];

    digest->len = 0;
    md5_begin(&md5);
    if ( bpc_fileZIO_open(&fd, fileName, 0, compress) ) {
	bpc_logErrf("bpc_fileDigest: can't open %s for reading\n", fileName);
	return -1;
    }
    while ( (nRead = bpc_fileZIO_read(&fd, buffer, sizeof(buffer))) > 0 ) {
	md5_update(&md5, buffer, nRead);
    }
    bpc_fileZIO_close(&fd);
    if ( nRead < 0 ) {
	bpc_logErrf("bpc_fileDigest: failed to read %s\n", fileName);
	return -1;
    }
    md5_result(&md5, digest->digest);
    digest->len = MD5_DIGEST_LEN;
    return 0;
}
