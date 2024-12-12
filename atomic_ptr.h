/*-------------------------------------------------------------------------
 *
 * atomic_ptr.h
 *	  Atomic pointer-size integer operations.
 *
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  contrib/sharena/atomic_ptr.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ATOMIC_PTR_H
#define ATOMIC_PTR_H

#include "postgres.h"
#include "port/atomics.h"

#if SIZEOF_VOID_P < 8
# define PG_UINTPTR_64		0
#else
# define PG_UINTPTR_64		1
#endif

/* An atomic marked pointer. */
#if !PG_UINTPTR_64
typedef uint32 pg_uintptr;
typedef pg_atomic_uint32 pg_atomic_uintptr;
#else
typedef uint64 pg_uintptr;
typedef pg_atomic_uint64 pg_atomic_uintptr;
#endif

static inline void
pg_atomic_init_uintptr(pg_atomic_uintptr *ptr, pg_uintptr value)
{
#if !PG_UINTPTR_64
	pg_atomic_init_u32(ptr, value);
#else
	pg_atomic_init_u64(ptr, value);
#endif
}

static inline pg_uintptr
pg_atomic_read_uintptr(pg_atomic_uintptr *ptr)
{
#if !PG_UINTPTR_64
	return pg_atomic_read_u32(ptr);
#else
	return pg_atomic_read_u64(ptr);
#endif
}

static inline void
pg_atomic_write_uintptr(pg_atomic_uintptr *ptr, pg_uintptr value)
{
#if !PG_UINTPTR_64
	pg_atomic_write_u32(ptr, value);
#else
	pg_atomic_write_u64(ptr, value);
#endif
}

static inline pg_uintptr
pg_atomic_exchange_uintptr(pg_atomic_uintptr *ptr, pg_uintptr value)
{
#if !PG_UINTPTR_64
	return pg_atomic_exchange_u32(ptr, value);
#else
	return pg_atomic_exchange_u64(ptr, value);
#endif
}

static inline bool
pg_atomic_compare_exchange_uintptr(pg_atomic_uintptr *ptr,
								   pg_uintptr *oldval, pg_uintptr newval)
{
#if !PG_UINTPTR_64
	return pg_atomic_compare_exchange_u32(ptr, oldval, newval);
#else
	return pg_atomic_compare_exchange_u64(ptr, oldval, newval);
#endif
}

#endif	/* ATOMIC_PTR_H */
