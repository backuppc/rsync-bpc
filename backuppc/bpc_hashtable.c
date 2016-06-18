/*
 * Routines to provide a memory-efficient hashtable.
 *
 * Copyright (C) 2007-2009 Wayne Davison
 *
 * Modified for BackupPC to use arbitrary-length binary keys, and supporting
 * a rudimentary delete feature by Craig Barratt.  In 6/2016 rewrote to
 * make the storage an array of pointers to entries, instead of inplace.
 * That way entries fetched from the hashtable are still value after a
 * resize.  Still no chaining.
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
 * Simple freelist of hash table entries.  We maintain a single linked list of
 * unused entries of each size, indexed by the FREELIST_SIZE2IDX() macro.
 *
 * FreeList[0] isn't used,
 * FreeList[1] is a free list of blocks of size 8,
 * FreeList[2] is a free list of blocks of size 16, ...
 *
 * eg, if you ask for a block of size 9, a block of size 16 will be returned.
 */
static bpc_hashtable_key **FreeList;
static uint32 FreeListSz;

/*
 * to map size to the FreeList index we round up to the nearest multiple of 8
 */
#define FREELIST_SIZE2IDX(size)         (((size) + 7) / 8)
#define FREELIST_IDX2SIZE(idx)          ((idx) * 8)
/*
 * how many new blocks to allocate when the free list is empty
 */
#define FREELIST_ALLOC_CNT              (512)

/*
 * allocate a single block of a given size by grabbing one off the FreeList
 */
static bpc_hashtable_key *bpc_hashtable_entryAlloc(uint32 size)
{
    uint32 freeListIdx;
    bpc_hashtable_key *key;

    freeListIdx = FREELIST_SIZE2IDX(size);
    size = FREELIST_IDX2SIZE(freeListIdx);
    if ( freeListIdx >= FreeListSz ) {
        /*
         * need a bigger array of freelists
         */
        if ( !(FreeList = (bpc_hashtable_key**)realloc(FreeList, 2 * freeListIdx * sizeof(bpc_hashtable_key*))) ) {
            bpc_logErrf("bpc_hashtable_entryAlloc: out of memory\n");
            return NULL;
        }
        memset(FreeList + FreeListSz, 0, (2 * freeListIdx - FreeListSz) * sizeof(bpc_hashtable_key*));
        FreeListSz = 2 * freeListIdx;
    }
    if ( !FreeList[freeListIdx] ) {
        char *newBuf;
        uint32 i;
        /*
         * need to populate the freelist with more blocks
         */
        if ( !(newBuf = (char*)malloc(size * FREELIST_ALLOC_CNT)) ) {
            bpc_logErrf("bpc_hashtable_entryAlloc: out of memory\n");
            return NULL;
        }
        FreeList[freeListIdx] = (bpc_hashtable_key*)newBuf;
        /*
         * chain all the buffers together in a linked list
         */
        for ( i = 0 ; i < FREELIST_ALLOC_CNT - 1 ; i++ ) {
            key = (bpc_hashtable_key*)newBuf;
            key->key = (void*)(newBuf + size);
            key = key->key;
        }
        key->key = NULL;
    }
    key = FreeList[freeListIdx];
    FreeList[freeListIdx] = key->key;
    memset(key, 0, size);
    return key;
}

/*
 * free a block of a given size by putting it back on the FreeList
 */
static void bpc_hashtable_entryFree(bpc_hashtable_key *key, uint32 size)
{
    uint32 freeListIdx;

    freeListIdx = FREELIST_SIZE2IDX(size);
    size = FREELIST_IDX2SIZE(freeListIdx);
    key->key = FreeList[freeListIdx];
    FreeList[freeListIdx] = key;
}

#define HASH_LOAD_LIMIT(size) ((size)*3/4)

/*
 * This implements a very simple linear hash table (no chaining etc).
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
    if ( !(tbl->nodes = calloc(size, sizeof(tbl->nodes[0]))) ) {
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
    uint32 i;
    for ( i = 0 ; i < tbl->size ; i++ ) {
        if ( tbl->nodes[i] ) {
            bpc_hashtable_entryFree(tbl->nodes[i], tbl->nodeSize);
        }
    }
    free(tbl->nodes);
}

void bpc_hashtable_erase(bpc_hashtable *tbl)
{
    uint32 i;
    for ( i = 0 ; i < tbl->size ; i++ ) {
        if ( tbl->nodes[i] ) {
            bpc_hashtable_entryFree(tbl->nodes[i], tbl->nodeSize);
        }
    }
    memset(tbl->nodes, 0, tbl->size * sizeof(tbl->nodes[0]));
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
    bpc_hashtable_key **node = tbl->nodes;
    uint i, entries = 0, entriesDel = 0;

    for ( i = 0 ; i < tbl->size ; i++, node++ ) {
        bpc_hashtable_key *keyInfo = *node;
        if ( !keyInfo ) {
            continue;
        }
        if ( !keyInfo->key && keyInfo->keyLen == 1 ) {
            entriesDel++;
        } else {
            entries++;
        }
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
    bpc_hashtable_key **old_nodes = tbl->nodes;
    bpc_hashtable_key **old_node  = tbl->nodes;
    uint32 oldSize  = tbl->size;
    uint i, j, ndx;

    /* Pick a power of 2 that can hold the requested newSize. */
    if ( (newSize & (newSize-1)) || newSize < 16 ) {
        uint32 req = newSize;
        newSize = 16;
        while ( newSize < req ) {
            newSize *= 2;
        }
    }
    if ( tbl->size >= newSize ) return;
    if ( !(tbl->nodes = (bpc_hashtable_key**)calloc(newSize, sizeof(tbl->nodes[0]))) ) {
        bpc_logErrf("bpc_hashtable_create: out of memory\n");
        return;
    }
    tbl->entries    = 0;
    tbl->entriesDel = 0;
    tbl->size       = newSize;

    for ( i = 0 ; i < oldSize ; i++, old_node++ ) {
        bpc_hashtable_key *keyInfo = *old_node;

        /* empty slot */
        if ( !keyInfo ) continue;

        /* deleted slot: free it and don't reinsert */
        if ( !keyInfo->key && keyInfo->keyLen == 1 ) {
            bpc_hashtable_entryFree(keyInfo, tbl->nodeSize);
            continue;
        }
        ndx = keyInfo->keyHash & (tbl->size - 1);
        for ( j = 0 ; j < tbl->size ; j++, ndx++ ) {
            if ( ndx >= tbl->size ) ndx = 0;
            if ( tbl->nodes[ndx] ) continue;
            tbl->nodes[ndx] = keyInfo;
            tbl->entries++;
            break;
        }
        if ( j >= tbl->size ) {
            bpc_logErrf("bpc_hashtable_growSize: botch on filling new hashtable (%d,%d)\n", newSize, tbl->entries);
            return;
        }
    }
    free(old_nodes);
}

/*
 * This returns the node for the indicated key, either newly created or
 * already existing.  Returns NULL if not allocating and not found.
 */
void *bpc_hashtable_find(bpc_hashtable *tbl, unsigned char *key, unsigned int keyLen, int allocate_if_missing)
{
    bpc_hashtable_key *keyInfo, *keyDeleted = NULL;
    uint32 i, ndx, keyHash;

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
    for ( i = 0 ; i < tbl->size ; i++ ) {
        keyInfo = tbl->nodes[ndx];

        if ( !keyInfo ) {
            /*
             * Not found since we hit an empty node (ie: not a deleted one)
             * If requested, place the new at a prior deleted node, or here
             */
            if ( allocate_if_missing ) {
                tbl->entries++;
                if ( keyDeleted ) {
                    /*
                     * we found a prior deleted entry, so use it instead
                     */
                    keyInfo = keyDeleted;
                    tbl->entriesDel--;
                } else {
                    tbl->nodes[ndx] = keyInfo = bpc_hashtable_entryAlloc(tbl->nodeSize);
                }
                keyInfo->key     = key;
                keyInfo->keyLen  = keyLen;
                keyInfo->keyHash = keyHash;
                /* TODO - check this? */
                if ( !key ) {
                    bpc_logErrf("bpc_hashtable_find: botch adding NULL key to hT (%d,%d)\n", tbl->size, tbl->nodeSize);
                }
                return (void*)keyInfo;
            }
            return (void*)NULL;
        } else {
            if ( !keyInfo->key && keyInfo->keyLen == 1 ) {
                if ( !keyDeleted ) {
                    /*
                     * this is the first deleted slot, which we remember so we can insert a new entry
                     * here if we don't find the desired entry, and allocate_if_missing != 0
                     */
                    keyDeleted = keyInfo;
                }
            } else if ( keyInfo->keyHash == keyHash && keyInfo->keyLen == keyLen && !memcmp(key, keyInfo->key, keyLen) ) {
                return (void*)keyInfo;
            }
        }
        ndx++;
        if ( ndx >= tbl->size ) ndx = 0;
    }
    return (void*)NULL;
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
    uint i, entries = 0, entriesDel = 0;

    /* bpc_hashttable_check(tbl, "iterate"); */

    for ( i = 0 ; i < tbl->size ; i++ ) {
        bpc_hashtable_key *keyInfo = tbl->nodes[i];

        if ( !keyInfo ) continue;
        if ( !keyInfo->key ) {
            if ( keyInfo->keyLen == 1 ) entriesDel++;
            continue;
        }
        (*callback)((void*)keyInfo, arg1);
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

    /* bpc_hashttable_check(tbl, "next entry"); */

    for ( ; i < (uint)tbl->size ; i++ ) {
        bpc_hashtable_key *keyInfo = tbl->nodes[i];
        if ( !keyInfo || !keyInfo->key ) continue;
        *idx = i + 1;
        return (void*)keyInfo;
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
