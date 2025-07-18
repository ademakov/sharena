/*-------------------------------------------------------------------------
 *
 * sharena.h
 *	  Shared dynamic memory allocation arena.
 *
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  contrib/sharena/sharena.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef SHARENA_H
#define SHARENA_H

#include "postgres.h"
#include "storage/ipc.h"

#if SIZEOF_SIZE_T < 8
# define SHAR_64			0
#else
# define SHAR_64			1
#endif

/* The shared arena block size. */
#define SHAR_BLOCK_SIZE		((Size) 32 * 1024)

/* The shared arena maximum chunk size. */
#define SHAR_CHUNK_SIZE_MAX	((Size) 16 * 1024)

/* The number of significant bits in a block number. */
#if !SHAR_64
# define SHAR_BLOCK_BITS	16
#else
# define SHAR_BLOCK_BITS	32
#endif

/* The minimum shared arena size. */
#define SHAR_TOTAL_SIZE_MIN	((Size) 1024 * SHAR_BLOCK_SIZE)

/* The maximum shared arena size. */
#define SHAR_TOTAL_SIZE_MAX	(((Size) 1 << SHAR_BLOCK_BITS) * SHAR_BLOCK_SIZE)

/* A shared arena block number. */
#if !SHAR_64
typedef uint16 SharBlock;
#else
typedef uint32 SharBlock;
#endif

Size
SharGetSize(void);

void
SharSetSize(Size);

void
SharAttach(void *base, Size size, bool init);

SharBlock
SharGetBlock(void);

void
SharPutBlock(SharBlock block);

SharBlock
SharGetBlockId(void *);

void *
SharGetBlockAddr(SharBlock block);

void *
SharAlloc(Size size);

void
SharFree(void *ptr);

Size
SharGetChunkSize(void *ptr);

/* ------------------------------------------------
 * Safe memory reclamation for lock-free algorithms
 */

#define SHAR_ENSURE_EPOCH_CLEANUP() \
	PG_ENSURE_ERROR_CLEANUP(SharEpochExitCB, 0)

#define SHAR_END_ENSURE_EPOCH_CLEANUP() \
	PG_END_ENSURE_ERROR_CLEANUP(SharEpochExitCB, 0)

void SharEpochBegin(void);
void SharEpochEnd(void);

void SharEpochExitCB(int code, Datum arg);
void SharEpochEnsureCleanup(void);
void SharEpochEndEnsureCleanup(void);

void SharRetire(void *ptr);

#endif	/* SHARENA_H */
