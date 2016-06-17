/*-------------------------------------------------------------------------
 *
 * sharena.c
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

#include "sharena.h"

#include "miscadmin.h"
#include "storage/ipc.h"

/*
 * The allocator is loosely based on the following paper:
 *
 * [2004] Maged M. Michael
 * Scalable Lock-Free Dynamic Memory Allocation
 *
 * As compared to the paper the allocator uses different terms -- "block"
 * instead of "superblock", "chunk" instead of "block", "alloc_state"
 * instead of "anchor", etc. More notable differences are:
 *
 * -- The block descriptors are preallocated based on the shared arena size
 * rather than dynamically allocated.
 *
 * -- It does not currently use ACTIVE per-process blocks. Chunk allocation
 * is done directly from shared partial blocks.
 *
 * -- Partial blocks are organized in lists using Heller's lock-based lazy
 * list algorithm. The original paper suggests to implement partial lists
 * with a lock-free algorithm together with hazard pointers.
 *
 * -- A partial block stays in a list during chunk allocation, it is removed
 * from the list only when it becomes full. At this moment it needs to be
 * synchronized with possible concurrent free calls. The current solution is
 * a busy wait loop inside the SharFree() function.
 *
 * The last two items digress from Michael's non-blocking allocator design.
 * Using hazard pointers and fully non-blocking design would complicate the
 * implementation considerably. The presumption is that block lists should
 * not suffer from high contention (unlike chunk lists), so the blocking
 * synchronization for them would be good enough.
 */

/* TODO: implement lock-protected chunk allocation as a fallback. */
#ifndef PG_HAVE_ATOMIC_U64_SUPPORT
# error "64-bit atomics are required for chunk allocation"
#endif

/* CPU cache line size. */
#ifdef __x86_64__
# define SHAR_CACHE_LINE	64
#else
# define SHAR_CACHE_LINE	PG_CACHE_LINE_SIZE
#endif

#define SHAR_EPOCH_LIMIT	64

/* The number of significant bits in a chunk index. */
#define SHAR_CHUNK_BITS		11
/* Invalid chunk index. */
#define	SHAR_CHUNK_NULL		PG_UINT16_MAX

/* The number of chunk size classes. */
#define SHAR_SZCLS_NUM		32
/* Pseudo-class to mark unused blocks. */
#define SHAR_SZCLS_FREE		255
/* Pseudo-class to mark whole blocks. */
#define SHAR_SZCLS_BLOCK	254

/* The number of bits used for a block allocation state. */
#define SHAR_STATE_BITS		2
/* Block allocation states. */
#define SHAR_STATE_ACTIVE	0 /* not currently used */
#define SHAR_STATE_PARTIAL	1
#define SHAR_STATE_FULL		2
#define SHAR_STATE_EMPTY	3

/* Definitions for layout of tagged block number. */
#define SHAR_BLOCK_CEILING	((SharTBlock) 1 << SHAR_BLOCK_BITS)
#define SHAR_BLOCK_VALMASK	(SHAR_BLOCK_CEILING - 1)
#define SHAR_BLOCK_TAGMASK	(~SHAR_BLOCK_VALMASK)

/* Definitions for layout of chunk allocation state. */
#define SHAR_COUNT_SHIFT	SHAR_CHUNK_BITS
#define SHAR_STATE_SHIFT	(2 * SHAR_CHUNK_BITS)
#define SHAR_CHUNK_MASK		(((SharChunk) 1 << SHAR_CHUNK_BITS) - 1)
#define SHAR_STATE_MASK		((1 << SHAR_STATE_BITS) - 1)
#define SHAR_ALLOC_BITS		(2 * SHAR_CHUNK_BITS + SHAR_STATE_BITS)
#define SHAR_ALLOC_CEILING	((SharState) 1 << SHAR_ALLOC_BITS)
#define SHAR_ALLOC_VALMASK	(SHAR_ALLOC_CEILING - 1)
#define SHAR_ALLOC_TAGMASK	(~SHAR_ALLOC_VALMASK)

/* Increment a block number tag. */
#define SHAR_BLOCK_INC(t)	((t) + SHAR_BLOCK_CEILING)

/* Assemble a tagged block number. */
#define SHAR_BLOCK_TAG(b, t)	\
	(((b) & SHAR_BLOCK_VALMASK) | ((t) & SHAR_BLOCK_TAGMASK))

/* Get the plain block number from a tagged one. */
#define SHAR_BLOCK_UNTAG(x)	((SharBlock)((x) & ~SHAR_BLOCK_TAGMASK))

/* Increment a chunk allocation state tag. */
#define SHAR_ALLOC_INC(t)	((t) + SHAR_ALLOC_CEILING)

/* Assemble a chunk allocation state. */
#define SHAR_ALLOC_TAG(c, n, s, t)						\
	(((c) & SHAR_CHUNK_MASK)							\
	 | (((n) & SHAR_CHUNK_MASK) << SHAR_COUNT_SHIFT)	\
	 | (((s) & SHAR_STATE_MASK) << SHAR_STATE_SHIFT)	\
	 | ((t) & SHAR_ALLOC_TAGMASK))

/* Get the chunk index from a chunk allocation state. */
#define SHAR_ALLOC_CHUNK(x)	((SharChunk) ((x) & SHAR_CHUNK_MASK))
/* Get the chunk count from a chunk allocation state. */
#define SHAR_ALLOC_COUNT(x)		\
	((SharChunk) (((x) >> SHAR_COUNT_SHIFT) & SHAR_CHUNK_MASK))
/* Get the block state from a chunk allocation state. */
#define SHAR_ALLOC_STATE(x)		\
	((uint8) (((x) >> SHAR_STATE_SHIFT) & SHAR_STATE_MASK))

/* Macros to atomically manipulate tagged block numbers. */
#if !SHAR_64
# define SHAR_BLOCK_INIT	pg_atomic_init_u32
# define SHAR_BLOCK_READ	pg_atomic_read_u32
# define SHAR_BLOCK_WRITE	pg_atomic_write_u32
# define SHAR_BLOCK_CAS		pg_atomic_compare_exchange_u32
#else
# define SHAR_BLOCK_INIT	pg_atomic_init_u64
# define SHAR_BLOCK_READ	pg_atomic_read_u64
# define SHAR_BLOCK_WRITE	pg_atomic_write_u64
# define SHAR_BLOCK_CAS		pg_atomic_compare_exchange_u64
#endif /* SHAR_64 */

/* Macros to atomically manipulate tagged chunk indexes. */
#define SHAR_ALLOC_INIT		pg_atomic_init_u64
#define SHAR_ALLOC_READ		pg_atomic_read_u64
#define SHAR_ALLOC_WRITE	pg_atomic_write_u64
#define SHAR_ALLOC_CAS		pg_atomic_compare_exchange_u64

/* The base shared arena address. */
#define SHAR_BASE			((uint8 *) shar_base)

/* Convert a block number into its descriptor. */
#define SHAR_BLOCK_DESC(b)	(shar_desc + (b))
/* Convert a block descriptor into its number. */
#define SHAR_DESC_BLOCK(d)	((d) - shar_desc)

/* Convert a block number into its address. */
#define SHAR_BLOCK_PTR(b)	(SHAR_BASE + (b) * SHAR_BLOCK_SIZE)
/* Convert an address into its block number. */
#define SHAR_PTR_BLOCK(a)	(((uint8 *) (a) - SHAR_BASE) / SHAR_BLOCK_SIZE)

/* Convert a chunk number into its address. */
#define SHAR_CHUNK_PTR(b, c, s)	((void *) (SHAR_BLOCK_PTR(b) + (c) * (s)))
/* Convert an address into its chunk number. */
#define SHAR_PTR_CHUNK(b, a, s)	(((uint8 *) (a) - SHAR_BLOCK_PTR(b)) / (s))

/* Convert size class index to the size class data. */
#define SHAR_SIZE_CLASS(i)	(&shar_base->classes[i - 1])

/* A tagged block index. */
#if !SHAR_64
typedef uint32 SharTBlock;
#else
typedef uint64 SharTBlock;
#endif

/* An atomic tagged block index. */
#if !SHAR_64
typedef pg_atomic_uint32 SharABlock;
#else
typedef pg_atomic_uint64 SharABlock;
#endif

/* A chunk number within a block. */
typedef uint16 SharChunk;

/* A chunk allocation state. */
typedef uint64 SharState;

/* An atomic chunk allocation state. */
typedef pg_atomic_uint64 SharAtomicState;

/* A block free list. */
typedef struct
{
	union
	{
		SharABlock	list;
		uint8		padding[SHAR_CACHE_LINE];
	};
} SharBlockFreeList;

/* A chunk size class. */
typedef struct
{
	/* A list of partial blocks. */
	union
	{
		LazyList list;
		uint8	padding[SHAR_CACHE_LINE];
	};
	/* Chunk size. */
	union
	{
		uint16	size;
		uint8	padding3[SHAR_CACHE_LINE];
	};
} SharClass;

/* A shared arena basic data. */
typedef struct
{
	/* The list of unused blocks. */
	SharBlockFreeList freelist;

	/* The lists of blocks with different chunk sizes. */
	SharClass	classes[SHAR_SZCLS_NUM];

	/* Global memory-reclamation epoch. */
	union
	{
		struct
		{
			pg_atomic_uint32 epoch;
			pg_atomic_uintptr limbo[3];
		};
		uint8	padding[SHAR_CACHE_LINE];
	};

	/* The total arena size (in blocks). */
	SharBlock  	total_size;
	/* The block index past the last used. */
	pg_atomic_uint32 next_block;
	/* The offset of descriptor and backend tables. */
	Size		desc_offset;
	Size		perbe_offset;
} SharBase;

/* A shared arena block descriptor. */
typedef struct
{
	/* A node in used block list. */
	LazyListNode used_node;
	/* A node in free block list. */
	SharABlock	free_node;
	/* A chunk allocation state. */
	SharAtomicState alloc_state;
	/* The size class index. */
	uint8		szcls_index;
} SharDesc;

/* A per-backend data. */
typedef struct
{
	/* Pending chunks. */
	void	   *limbo[2];
	uint32		count[2];
	/* Local memory-reclamation epoch. */
	pg_atomic_uint32 epoch;
	/* Backend activity flag. */
	pg_atomic_flag state;
} SharPerBE;

/* The shared arena header and base address as well. */
static SharBase *shar_base = NULL;

/* Table of block descriptors. */
SharDesc  *shar_desc;

/* Table of per-backend data. */
SharPerBE *shar_perbe;

/* The shared arena size (in blocks). */
static SharBlock shar_size = 8 * SHAR_TOTAL_SIZE_MIN;

static uint16 shar_chunk_sizes[] = {
	16,   32,   48,   64,   80,   96,   112,  128,
	160,  192,  224,  256,  320,  384,  448,  512,
	640,  768,  896,  1024, 1280, 1536, 1792, 2048,
	2560, 3072, 3584, 4096, 5120, 6144, 8192, 16384
};

/*
 * Get the total shared arena size.
 */
Size
SharGetSize(void)
{
	return shar_size;
}

/*
 * Get the desired shared arena size. If the arena has already been
 * created then this function has no effect.
 */
void
SharSetSize(Size size)
{
	if (shar_base != NULL)
		return;

	/* Size sanity check. */
	if (size < SHAR_TOTAL_SIZE_MIN)
		size = SHAR_TOTAL_SIZE_MIN;
	else if (size > SHAR_TOTAL_SIZE_MAX)
		size = SHAR_TOTAL_SIZE_MAX;

	/* Round the size to a block multiple. */
	shar_size = (size + SHAR_BLOCK_SIZE - 1) & ~(Size)(SHAR_BLOCK_SIZE - 1);
}

static void
SharInit(Size size)
{
	Size		desc_size, perbe_size;
	Size		reserved_size;
	SharBlock	nreserved;
	SharPerBE  *be;
	Index		i;

	/* Round the size to a block multiple. */
	shar_base->total_size = size / SHAR_BLOCK_SIZE;

	/* Calculate the space required for block descriptors. */
	desc_size = shar_base->total_size * sizeof(SharDesc);
	/* Calculate the space required for per-backend data. */
	perbe_size = (MaxBackends + 1) * sizeof(SharPerBE);

	/* Calculate block and epoch table offsets */
	reserved_size = TYPEALIGN(SHAR_CACHE_LINE, sizeof(SharBase));
	shar_base->desc_offset = reserved_size;
	reserved_size += TYPEALIGN(SHAR_CACHE_LINE, desc_size);
	shar_base->perbe_offset = reserved_size;
	reserved_size += TYPEALIGN(SHAR_CACHE_LINE, perbe_size);

	/* Calculate the number of blocks reserved for meta data. */
	nreserved = TYPEALIGN(SHAR_BLOCK_SIZE, reserved_size) / SHAR_BLOCK_SIZE;
	elog(DEBUG1, "reserved %u blocks in shared arena (%lu %lu %lu)",
		 nreserved, sizeof(SharBase), desc_size, perbe_size);
	Assert(nreserved < shar_base->total_size);

	/* Initialize the info about free blocks. */
	pg_atomic_init_u32(&shar_base->next_block, nreserved);
	SHAR_BLOCK_INIT(&shar_base->freelist.list, 0);

	/* Initialize the info about size class lists. */
	for (i = 0; i < SHAR_SZCLS_NUM; i++)
	{
		LazyListInit(&shar_base->classes[i].list);
		shar_base->classes[i].size = shar_chunk_sizes[i];
	}

	/* Initialize the global reclamation epoch. */
	pg_atomic_init_u32(&shar_base->epoch, 0);

	/* Initialize the per-backend info. */
	be = (SharPerBE *) (SHAR_BASE + shar_base->perbe_offset);
	for (i = 0; i <= MaxBackends; i++)
	{
		pg_atomic_init_flag(&be[i].state);
	}
}

/*
 * Attach to a newly created or pre-existing shared arena.
 */
void
SharAttach(void *base, Size size, bool init)
{
	/* Bail out if already attached. */
	if (shar_base != NULL)
		return;

	elog(DEBUG1, "!!! shmem attach %p %lu !!!", base, size);

	/* Setup the base address. */
	shar_base = (SharBase *) base;

	/* Initialize a newly created arena. */
	if (init)
		SharInit(size);

	shar_desc = (SharDesc *) (SHAR_BASE + shar_base->desc_offset);
	shar_perbe = (SharPerBE *) (SHAR_BASE + shar_base->perbe_offset);

	/* Update the size info. */
	shar_size = shar_base->total_size * SHAR_BLOCK_SIZE;
}

SharBlock
SharGetBlock(void)
{
	SharDesc   *desc;
	SharBlock	block;
	SharTBlock	oldtop, newtop;

	/* Get a block from the free list using the Treiber stack algorithm. */
	oldtop = SHAR_BLOCK_READ(&shar_base->freelist.list);
	while ((block = SHAR_BLOCK_UNTAG(oldtop)) != 0)
	{
		desc = SHAR_BLOCK_DESC(block);
		newtop = SHAR_BLOCK_TAG(SHAR_BLOCK_READ(&desc->free_node),
								SHAR_BLOCK_INC(oldtop));
		if (SHAR_BLOCK_CAS(&shar_base->freelist.list, &oldtop, newtop))
			break;
	}

	/* Allocate a new block if the free list is empty. */
	if (!block)
	{
		SharBlock next = pg_atomic_read_u32(&shar_base->next_block);
		if (next < shar_base->total_size)
		{
			/* Optimistically allocate a next block. */
			block = pg_atomic_fetch_add_u32(&shar_base->next_block, 1);
			if (block >= shar_base->total_size || block < next)
			{
				/* Got invalid block index. Undo. */
				pg_atomic_fetch_sub_u32(&shar_base->next_block, 1);
				return 0;
			}
		}
	}

	/* Mark the block as used. */
	desc = SHAR_BLOCK_DESC(block);
	desc->szcls_index = SHAR_SZCLS_BLOCK;

	elog(DEBUG4, "SharGetBlock: %d", block);
	return block;
}

void
SharPutBlock(SharBlock block)
{
	SharDesc   *desc;
	SharTBlock	oldtop, newtop;

	elog(DEBUG4, "SharPutBlock: %d", block);

	/* Mark the block as unused. */
	desc = SHAR_BLOCK_DESC(block);
	desc->szcls_index = SHAR_SZCLS_FREE;

	/* Put the block in the free list using the Treiber stack algorithm. */
	oldtop = SHAR_BLOCK_READ(&shar_base->freelist.list);
	while (1)
	{
		newtop = SHAR_BLOCK_TAG(block, oldtop);
		SHAR_BLOCK_WRITE(&desc->free_node, oldtop);
		if (SHAR_BLOCK_CAS(&shar_base->freelist.list, &oldtop, newtop))
			break;
	}
}

SharBlock
SharGetBlockId(void *ptr)
{
	if ((uint8 *) ptr < SHAR_BASE)
		return 0;
	if ((uint8 *) ptr >= SHAR_BASE + SharGetSize())
		return 0;
	return SHAR_PTR_BLOCK(ptr);
}

void *
SharGetBlockAddr(SharBlock block)
{
	if (block == 0)
		return NULL;
	if (block >= shar_base->total_size)
		return NULL;
	return SHAR_BLOCK_PTR(block);
}

static uint16
SharGetSizeClassIndex(Size size)
{
	if (size <= 1024)
	{
		if (size <= 256)
		{
			if (size <= 128)
				return ((size + 15 + (size == 0)) / 16);
			else
				return (size + 31) / 32 + 4;
		}
		else
		{
			if (size <= 512)
				return (size + 63) / 64 + 8;
			else
				return (size + 127) / 128 + 12;
		}
	}
	else
	{
		if (size <= 4096)
		{
			if (size <= 2048)
				return (size + 255) / 256 + 16;
			else
				return (size + 511) / 512 + 20;
		}
		else if (size <= SHAR_CHUNK_SIZE_MAX)
		{
			if (size <= 6144)
				return (size + 1023) / 1024 + 24;
			else
				return (size <= 8192) ? 31 : 32;
		}
	}
	return 0;
}

/*
 * Prepare a block for chunk allocation and allocate the first chunk from it.
 */
static SharChunk
SharStartBlock(SharBlock block, uint16 szcls_index, SharClass *szcls)
{
	uint16		size = szcls->size;
	SharDesc   *desc = SHAR_BLOCK_DESC(block);
	SharChunk	total, chunk;
	SharState	alloc;

	/* Find out the number of chunks that fit into a block. */
	total = SHAR_BLOCK_SIZE / size;
	Assert(count > 1);

	/* Prepare the chunk allocation state taking into account that
	   the chunk with index 0 is allocated right away. */
	alloc = SHAR_ALLOC_TAG(1, total - 1, SHAR_STATE_PARTIAL, 0);

	/* Organize chunks in a linked list from index 1 to the block end. */
	for (chunk = 1; chunk < total - 1; chunk++)
		*((SharChunk *) SHAR_CHUNK_PTR(block, chunk, size)) = chunk + 1;
	*((SharChunk *) SHAR_CHUNK_PTR(block, total - 1, size)) = SHAR_CHUNK_NULL;

	/* Initialize the block descriptor. */
	SHAR_ALLOC_INIT(&desc->alloc_state, alloc);
	desc->szcls_index = szcls_index;

	/* Return the index of allocated chunk. */
	return 0;
}

static SharDesc *
SharGetPartial(SharClass  *szcls)
{
	LazyListIterator iter;
	LazyListNode *curr;

	curr = LazyListBegin(&iter, &szcls->list);
	while (curr != NULL) {
		SharDesc *desc = (SharDesc *) curr;
		SharState alloc = SHAR_ALLOC_READ(&desc->alloc_state);
		if (SHAR_ALLOC_STATE(alloc) == SHAR_STATE_PARTIAL)
			return desc;
		curr = LazyListNext(&iter);
	}
	return NULL;
}

/*
 * Allocate a memory chunk.
 */
void *
SharAlloc(Size size)
{
	uint16		index;
	SharClass  *szcls;
	SharBlock	block;
	SharChunk	chunk;
	void	   *ptr;

	/* Determine the required size class. */
	index = SharGetSizeClassIndex(size);
	if (index == 0)
		return NULL;
	szcls = SHAR_SIZE_CLASS(index);

	for (;;)
	{
		SharDesc *desc;
		SharState oldalloc;

		/* Get a partial block for the class. */
		desc = SharGetPartial(szcls);
		if (desc == NULL)
		{
			/* Allocate a new block if there is none. */
			block = SharGetBlock();
			if (block == 0)
			{
				/* TODO: try with a larger size class. */
				return NULL;
			}

			/* Prepare it for chunk allocation and allocate the first one. */
			chunk = SharStartBlock(block, index, szcls);
			desc = SHAR_BLOCK_DESC(block);

			/* Store the new block in the partial list. */
			if (!LazyListInsert(&szcls->list, &desc->used_node))
			{
				ereport(PANIC,
						(errcode(ERRCODE_FDW_ERROR),
						 errmsg("shared arena memory corruption")));
			}
			goto success;
		}

		/* Get a chunk from the block using the Treiber stack algorithm. */
		block = SHAR_DESC_BLOCK(desc);
		oldalloc = SHAR_ALLOC_READ(&desc->alloc_state);
		for (;;)
		{
			SharState newalloc;
			SharChunk newchunk, oldcount, newcount;
			uint8 oldstate, newstate;

			chunk = SHAR_ALLOC_CHUNK(oldalloc);
			oldcount = SHAR_ALLOC_COUNT(oldalloc);
			oldstate = SHAR_ALLOC_STATE(oldalloc);
			if (oldstate != SHAR_STATE_PARTIAL)
				break;
			newcount = oldcount - 1;
			if (newcount)
			{
				newstate = SHAR_STATE_PARTIAL;
				newchunk = *((SharChunk *) SHAR_CHUNK_PTR(block, chunk,
														  szcls->size));
			}
			else
			{
				newstate = SHAR_STATE_FULL;
				newchunk = 0;
			}

			newalloc = SHAR_ALLOC_TAG(newchunk, newcount, newstate,
									  SHAR_ALLOC_INC(oldalloc));
			if (SHAR_ALLOC_CAS(&desc->alloc_state, &oldalloc, newalloc))
			{
				if (newstate == SHAR_STATE_FULL)
				{
					if (!LazyListRemove(&szcls->list, &desc->used_node))
					{
						ereport(PANIC,
								(errcode(ERRCODE_FDW_ERROR),
								 errmsg("shared arena memory corruption")));
					}

					/* Synchronize with possible concurrent SharFree() calls. */
					pg_write_barrier();
					newalloc = SHAR_ALLOC_TAG(1, newcount, newstate, newalloc);
					SHAR_ALLOC_WRITE(&desc->alloc_state, newalloc);
				}
				goto success;
			}
		}
	}

success:
	ptr = SHAR_CHUNK_PTR(block, chunk, szcls->size);
	elog(DEBUG4, "SharAlloc: size %lu/%d, block %d, chunk %d, ptr %p",
		 size, szcls->size, block, chunk, ptr);
	return ptr;
}

/*
 * Free a memory chunk.
 */
void
SharFree(void *ptr)
{
	SharBlock	block;
	SharDesc   *desc;
	SharClass  *szcls;
	SharChunk	chunk, total;
	SharState	oldalloc;

	/* Bail out on a NULL pointer. */
	if (ptr == NULL)
		return;

	/* Find the block that contains the given pointer. */
	block = SHAR_PTR_BLOCK(ptr);
	Assert(block > 0 && block < shar_base->total_size);
	/* Find the associated block descriptor. */
	desc = SHAR_BLOCK_DESC(block);
	Assert(desc->szcls_index < SHAR_SZCLS_NUM);

	/* Find the chunk size class and index. */
	szcls = SHAR_SIZE_CLASS(desc->szcls_index);
	chunk = SHAR_PTR_CHUNK(block, ptr, szcls->size);
	/* Find out the number of chunks that fit into a block. */
	total = SHAR_BLOCK_SIZE / szcls->size;

	elog(DEBUG4, "SharFree: size %d, block %d, chunk %d, ptr %p",
		 szcls->size, block, chunk, ptr);

	/* Free the chunk using the Treiber stack algorithm. */
	oldalloc = SHAR_ALLOC_READ(&desc->alloc_state);
	for (;;)
	{
		SharChunk oldchunk, oldcount, newcount;
		uint8 oldstate, newstate;
		SharState newalloc;

		oldchunk = SHAR_ALLOC_CHUNK(oldalloc);
		oldcount = SHAR_ALLOC_COUNT(oldalloc);
		oldstate = SHAR_ALLOC_STATE(oldalloc);
		if (oldstate == SHAR_STATE_FULL)
		{
			/* Synchronize with a possible concurrent SharAlloc() call. */
			if (oldchunk == 0)
			{
				pg_spin_delay();
				oldalloc = SHAR_ALLOC_READ(&desc->alloc_state);
				continue;
			}

			newcount = 1;
			newstate = SHAR_STATE_PARTIAL;
		}
		else if (oldcount == (total - 1))
		{
			newcount = 0;
			newstate = SHAR_STATE_EMPTY;
		}
		else
		{
			newcount = oldcount + 1;
			newstate = oldstate;
		}

		*((SharChunk *) ptr) = oldchunk;
		newalloc = SHAR_ALLOC_TAG(chunk, newcount, newstate, oldalloc);
		if (SHAR_ALLOC_CAS(&desc->alloc_state, &oldalloc, newalloc))
		{
			if (newstate == SHAR_STATE_EMPTY)
			{
				/* Just freed the last used chunk in the block. So now free
				   the block itself. First remove it from the PARTIAL block
				   list. */
				if (!LazyListRemove(&szcls->list, &desc->used_node))
				{
					ereport(PANIC,
							(errcode(ERRCODE_FDW_ERROR),
							 errmsg("shared arena memory corruption")));
				}
				/* And finally put it to the free list. */
				SharPutBlock(block);
			}
			else if (oldstate == SHAR_STATE_FULL)
			{
				/* Just freed a used chunk from a full block. So now move
				   it to the PARTIAL list. */
				if (!LazyListInsert(&szcls->list, &desc->used_node))
				{
					ereport(PANIC,
							(errcode(ERRCODE_FDW_ERROR),
							 errmsg("shared arena memory corruption")));
				}
			}
			break;
		}
	}
}

static SharPerBE *
SharGetBackend(void)
{
	return &shar_perbe[MyBackendId];
}

static void
SharLimboFree(void *limbo)
{
	while (limbo != NULL)
	{
		void *next = *((void **) limbo);
		SharFree(limbo);
		limbo = next;
	}
}

static void
SharGlobalLimboFree(pg_uintptr limbo)
{
	SharLimboFree(markptr_ptr(limbo));
}

static bool
SharEpochUpdate(SharPerBE *be, uint32_t epoch)
{
	bool update = (epoch != pg_atomic_read_u32(&be->epoch));
	if (update)
	{
		uint32 slot = epoch & 1;
		pg_atomic_write_u32(&be->epoch, epoch);
		SharLimboFree(be->limbo[slot]);
		be->limbo[slot] = NULL;
		be->count[slot] = 0;
	}
	return update;
}

static bool
SharEpochAdvance(SharPerBE *be)
{
	uint32_t	epoch;
	int			i;

	epoch = pg_atomic_read_u32(&shar_base->epoch);
	pg_read_barrier();

	/* Check if all backends reached the global epoch. */
	for (i = 0; i <= MaxBackends; i++)
	{
		SharPerBE *be2 = &shar_perbe[i];

		/* Skip any inactive backend. */
		if (pg_atomic_unlocked_test_flag(&be2->state))
			continue;

		/* Bail out if the global epoch is not reached yet. */
		if (epoch != pg_atomic_read_u32(&be2->epoch))
			return false;
	}

	/* Update the global epoch. */
	if (pg_atomic_exchange_u32(&shar_base->epoch, epoch + 1) == epoch)
	{
		int slot;
		pg_uintptr mptr;
		slot = (epoch + 1) % 3;
		mptr = pg_atomic_exchange_uintptr(&shar_base->limbo[slot],
										 markptr_make(NULL, 0));
		SharGlobalLimboFree(mptr);
	}

	/* Update the local epoch. */
	SharEpochUpdate(be, epoch + 1);

	return true;
}

static void
SharEpochTransfer(SharPerBE *be, uint32_t epoch)
{
	int src_slot = epoch & 1;
	if (be->count[src_slot])
	{
		void *limbo = be->limbo[src_slot];
		int dst_slot = epoch % 3;

		while (limbo != NULL)
		{
			void *next = *((void **) limbo);
			pg_uintptr newtop = markptr_make(limbo, 0);
			pg_uintptr oldtop = pg_atomic_read_uintptr(&shar_base->limbo[dst_slot]);
			do
				*((void **) limbo) = markptr_ptr(oldtop);
			while (!pg_atomic_compare_exchange_uintptr(&shar_base->limbo[dst_slot],
													  &oldtop, newtop));
			limbo = next;
		}

		be->limbo[src_slot] = NULL;
		be->count[src_slot] = 0;
	}
}

static void
SharEpochBeginInternal(SharPerBE *be)
{
	if (pg_atomic_unlocked_test_flag(&be->state))
	{
		/* Set the activity flag. It is accessed only by single backend
		   so it must succeed. The atomic is used to ensure the acquire
		   semantics. */
		pg_atomic_test_set_flag(&be->state);

		/* Update the local epoch if needed. */
		SharEpochUpdate(be, pg_atomic_read_u32(&shar_base->epoch));
	}
}

void
SharEpochBegin(void)
{
	SharEpochBeginInternal(SharGetBackend());
}

void
SharEpochEnd(void)
{
	SharPerBE  *be = SharGetBackend();
	uint32_t	epoch;

	/* Update the local epoch if possible. */
	SharEpochUpdate(be, pg_atomic_read_u32(&shar_base->epoch));
	/* Bump the global epoch if possible. */
	SharEpochAdvance(be);

	/* Move chunks from local to global limbo slots. */
	epoch = pg_atomic_read_u32(&be->epoch);
	SharEpochTransfer(be, epoch - 1);
	SharEpochTransfer(be, epoch);

	elog(DEBUG4, "backend %d, epoch %u", MyBackendId, epoch);

	/* Release the current backend. */
	pg_atomic_clear_flag(&be->state);
}

/*
 * Safely free a memory chunk.
 */
void
SharRetire(void *ptr)
{
	SharPerBE  *be;
	uint32		slot;

	/* Bail out on a NULL pointer. */
	if (ptr == NULL)
		return;

	elog(DEBUG4, "SharRetire: %p", ptr);

	/* Get the current backend record. */
	be = SharGetBackend();
	SharEpochBeginInternal(be);

	/* Put the chunk into a limbo list. */
	slot = pg_atomic_read_u32(&be->epoch) & 1;
	*((void **) ptr) = be->limbo[slot];
	be->limbo[slot] = ptr;
	be->count[slot]++;

	/* Free some chunks if there are too many of them already. */
	if ((be->count[0] + be->count[1]) > SHAR_EPOCH_LIMIT)
	{
		/* Update the local epoch if feasible. */
		if (!SharEpochUpdate(be, pg_atomic_read_u32(&shar_base->epoch)))
		{
			/* Otherwise try to bump the global epoch. */
			SharEpochAdvance(be);
		}
	}
}

void
SharEpochExitCB(int code, Datum arg)
{
	SharEpochEnd();
}

void
SharEpochEnsureCleanup()
{
	before_shmem_exit(SharEpochExitCB, 0);
}

void
SharEpochEndEnsureCleanup()
{
	cancel_before_shmem_exit(SharEpochExitCB, 0);
}
