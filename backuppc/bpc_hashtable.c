/*
 * Routines to provide a memory-efficient hashtable.
 *
 * Copyright (C) 2007-2009 Wayne Davison
 *
 * Modified for BackupPC to use arbitrary-length binary keys, and supporting
 * a rudimentary delete feature by Craig Barratt.
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

#define HASH_LOAD_LIMIT(size) ((size)*3/4)

/*
 * This implements a very simple linear hash table (in place, no chaining etc).
 *
 * It has rudimentary support for delete, by flagging the deleted node.  It doesn't
 * shift other nodes on delete, but can re-use a deleted node on insert.
 */

/*
 * Create a hash table of the initial given size, with entries of size nodeSize
 */
void bpc_hashtable_create(bpc_hashtable *tbl, uint32 size, uint32 nodeSize)
{
    /* Pick a power of 2 that can hold the requested size. */
    if ( (size & (size-1)) || size < 16 ) {
        uint32 req = size;
        size = 16;
        while ( size < req ) {
            size *= 2;
        }
    }
    if ( !(tbl->nodes = calloc(size, nodeSize)) ) {
        bpc_logErrf("bpc_hashtable_create: out of memory\n");
        return;
    }
    tbl->size       = size;
    tbl->entries    = 0;
    tbl->entriesDel = 0;
    tbl->nodeSize   = nodeSize;

    return;
}

void bpc_hashtable_destroy(bpc_hashtable *tbl)
{
    free(tbl->nodes);
}

void bpc_hashtable_erase(bpc_hashtable *tbl)
{
    memset(tbl->nodes, 0, tbl->size * tbl->nodeSize);
    tbl->entries    = 0;
    tbl->entriesDel = 0;
}

/*
 * Compute a hash for a given key.  Note that it is *not* modulo the table size - the returned
 * hash is independent of the table size, so we don't have to recompute this hash if we
 * resize the table.  However, the current implementation does recompute the hash when
 * we resize the hash table :(.  Oh well.
 */
uint32 bpc_hashtable_hash(uchar *key, uint32 keyLen)
{
    /* Based on Jenkins One-at-a-time hash. */
    uint32 ndx;

    for ( ndx = 0 ; keyLen > 0 ; keyLen-- ) {
        ndx += *key++;
        ndx += (ndx << 10);
        ndx ^= (ndx >> 6);
    }
    ndx += (ndx << 3);
    ndx ^= (ndx >> 11);
    ndx += (ndx << 15);

    return ndx;
}

#if 0
static void bpc_hashttable_check(bpc_hashtable *tbl, char *str)
{
    uchar *node = tbl->nodes;
    uint i, entries = 0, entriesDel = 0;

    for ( i = 0 ; i < tbl->size ; i++, node += tbl->nodeSize ) {
        bpc_hashtable_key *keyInfo = (bpc_hashtable_key*)node;
        if ( !keyInfo->key ) {
            if ( keyInfo->keyLen == 1 ) entriesDel++;
            continue;
        }
        entries++;
    }
    if ( entries != tbl->entries ) {
        bpc_logErrf("bpc_hashttable_check: botch at %s on HT (%u,%u): got %u entries vs %u expected\n",
                                str, tbl->size, tbl->nodeSize, entries, tbl->entries);
        tbl->entries = entries;
    }
    if ( entriesDel != tbl->entriesDel ) {
        bpc_logErrf("bpc_hashttable_check: botch at %s on HT (%u,%u): got %u entriesDel vs %u expected\n",
                                str, tbl->size, tbl->nodeSize, entriesDel, tbl->entriesDel);
        tbl->entriesDel = entriesDel;
    }
}
#endif

/*
 * Ensure the hash table is of size at least newSize
 */
void bpc_hashtable_growSize(bpc_hashtable *tbl, uint32 newSize)
{
    void *old_nodes = tbl->nodes, *node;
    void *old_node  = tbl->nodes;
    uint32 oldSize  = tbl->size;
    uint i;

    /* Pick a power of 2 that can hold the requested newSize. */
    if ( (newSize & (newSize-1)) || newSize < 16 ) {
        uint32 req = newSize;
        newSize = 16;
        while ( newSize < req ) {
            newSize *= 2;
        }
    }
    if ( tbl->size >= newSize ) return;
    if ( !(tbl->nodes = calloc(newSize, tbl->nodeSize)) ) {
        bpc_logErrf("bpc_hashtable_create: out of memory\n");
        return;
    }
    tbl->entries    = 0;
    tbl->entriesDel = 0;
    tbl->size       = newSize;

    for ( i = 0 ; i < oldSize ; i++, old_node += tbl->nodeSize ) {
        bpc_hashtable_key *keyInfo = (bpc_hashtable_key*)old_node;
        if ( !keyInfo->key ) continue;

        node = bpc_hashtable_find(tbl, keyInfo->key, keyInfo->keyLen, 1);
        /*
         * if the key points inside this node, adjust the address for the new node
         */
        if ( old_node <= keyInfo->key && keyInfo->key < old_node + tbl->nodeSize ) {
            keyInfo->key += node - old_node;
        }
        memcpy(node, old_node, tbl->nodeSize);
    }
    free(old_nodes);
}

/*
 * This returns the node for the indicated key, either newly created or
 * already existing.  Returns NULL if not allocating and not found.
 */
void *bpc_hashtable_find(bpc_hashtable *tbl, unsigned char *key, unsigned int keyLen, int allocate_if_missing)
{
    uchar *node;
    bpc_hashtable_key *keyInfo, *keyDeleted = NULL;
    uint32 ndx, keyHash;

    if ( allocate_if_missing && tbl->entries + tbl->entriesDel > HASH_LOAD_LIMIT(tbl->size) ) {
        bpc_hashtable_growSize(tbl, tbl->size * 2);
    }

    /* bpc_hashttable_check(tbl, "find"); */

    /*
     * If it already exists, return the node.  If we're not
     * allocating, return NULL if the key is not found.
     */
    ndx = keyHash = bpc_hashtable_hash(key, keyLen);
    ndx &= tbl->size - 1;
    node = (uchar*)tbl->nodes + ndx * tbl->nodeSize;
    while ( 1 ) {
        keyInfo = (bpc_hashtable_key*)node;

        if ( !keyInfo->key ) {
            if ( keyInfo->keyLen == 0 ) {
                /*
                 * Not found since we hit a truly empty node (ie: not a deleted one)
                 * If requested, place the new at a prior deleted node, or here
                 */
                if ( allocate_if_missing ) {
                    tbl->entries++;
                    if ( keyDeleted ) {
                        /*
                         * we found a prior deleted entry, so use it instead
                         */
                        keyInfo = keyDeleted;
                        node    = (void*)keyDeleted;
                        tbl->entriesDel--;
                    }
                    keyInfo->key     = key;
                    keyInfo->keyLen  = keyLen;
                    keyInfo->keyHash = keyHash;
                    if ( !key ) {
                        bpc_logErrf("bpc_hashtable_find: botch adding NULL key to hT (%d,%d)\n", tbl->size, tbl->nodeSize);
                    }
                    return (void*)node;
                }
                return (void*)NULL;
            } else if ( !keyDeleted ) {
                /*
                 * this is the first deleted slot, which we remember so we can insert a new entry
                 * here if we don't find the desired entry, and allocate_if_missing != 0
                 */
                keyDeleted = keyInfo;
            }
        } else if ( keyInfo->keyHash == keyHash && keyInfo->keyLen == keyLen && !memcmp(key, keyInfo->key, keyLen) ) {
            return (void*)node;
        }
        ndx++;
        node += tbl->nodeSize;
        if ( ndx >= tbl->size ) {
            ndx = 0;
            node = (uchar*)tbl->nodes;
        }
    }
}

/*
 * Remove a node from the hash table.  Node must be a valid node returned by bpc_hashtable_find!
 * Node gets cleared.
 */
void bpc_hashtable_nodeDelete(bpc_hashtable *tbl, void *node)
{
    bpc_hashtable_key *keyInfo = (bpc_hashtable_key*)node;

    memset(node, 0, tbl->nodeSize);
    /*
     * special delete flag (key is NULL, keyLen is 1), so that the linear hash table continues
     * finding entries past this point.
     * TODO optimization: if the next entry is empty, then we can make this empty too.
     */
    keyInfo->keyLen = 1;
    tbl->entries--;
    tbl->entriesDel++;

    /* bpc_hashttable_check(tbl, "delete"); */
}

/*
 * Iterate over all the entries in the hash table, calling a callback for each valid entry
 *
 * Note: this function won't work if the callback adds new entries to the hash table while
 * iterating over the entries.  You can update or delete entries, but adding an entry might
 * cause the * hash table size to be bumped, which breaks the indexing.  So don't add new
 * entries while iterating over the table.
 */
void bpc_hashtable_iterate(bpc_hashtable *tbl, void (*callback)(void*, void*), void *arg1)
{
    uchar *node = tbl->nodes;
    uint i, entries = 0, entriesDel = 0;

    /* bpc_hashttable_check(tbl, "iterate"); */

    for ( i = 0 ; i < tbl->size ; i++, node += tbl->nodeSize ) {
        bpc_hashtable_key *keyInfo = (bpc_hashtable_key*)node;
        if ( !keyInfo->key ) {
            if ( keyInfo->keyLen == 1 ) entriesDel++;
            continue;
        }
        (*callback)((void*)node, arg1);
        if ( !keyInfo->key ) {
            if ( keyInfo->keyLen == 1 ) entriesDel++;
            continue;
        } else {
            entries++;
        }
    }
    if ( entries != tbl->entries ) {
        bpc_logErrf("bpc_hashtable_iterate: botch on HT (%u,%u): got %u entries vs %u expected\n",
                                tbl->size, tbl->nodeSize, entries, tbl->entries);
        tbl->entries = entries;
    }
    if ( entriesDel != tbl->entriesDel ) {
        bpc_logErrf("bpc_hashtable_iterate: botch on HT (%u,%u): got %u entriesDel vs %u expected\n",
                                tbl->size, tbl->nodeSize, entriesDel, tbl->entriesDel);
        tbl->entriesDel = entriesDel;
    }
}

/*
 * An alternative way to iterate over all the hash table entries.  Initially index should
 * be zero, and is updated on each call.  A pointer to each entry is returned.  After
 * the last entry, NULL is returned, and idx is set back to zero.
 *
 * Note: this function won't work if you add new entries to the hash table while iterating
 * over the entries.  You can update or delete entries, but adding an entry might cause the
 * hash table size to be bumped, which breaks the indexing.  So don't add new entries while
 * iterating over the table.
 */
void *bpc_hashtable_nextEntry(bpc_hashtable *tbl, uint *idx)
{
    uint i = *idx;
    uchar *node;

    /* bpc_hashttable_check(tbl, "next entry"); */

    node = tbl->nodes + i * tbl->nodeSize;
    for ( ; i < (uint)tbl->size ; i++, node += tbl->nodeSize ) {
        bpc_hashtable_key *keyInfo = (bpc_hashtable_key*)node;
        if ( !keyInfo->key ) continue;
        *idx = i + 1;
        return node;
    }
    *idx = 0;
    return NULL;
}

/*
 * Return the number of entries in the hash table
 */
int bpc_hashtable_entryCount(bpc_hashtable *tbl)
{
    /* bpc_hashttable_check(tbl, "entryCount"); */
    return tbl->entries;
}
