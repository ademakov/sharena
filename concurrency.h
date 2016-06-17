/*-------------------------------------------------------------------------
 *
 * atomic_ptr.h
 *	  Concurrency support.
 *
 *
 * Copyright (c) 2016, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  contrib/sharena/concurrency.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef CONCURRENCY_H
#define CONCURRENCY_H

#include "postgres.h"
#include "atomic_ptr.h"
#include "storage/spin.h"

/* ---------------
 * Marked pointers
 */

/* Marked pointer required alignment. */
#define MARKPTR_ALIGN		8
/* Bit mask for marked pointer mark value. */
#define MARKPTR_MASK		(MARKPTR_ALIGN - 1)

static inline void *
markptr_ptr(pg_uintptr mptr)
{
	return (void *) (mptr & ~MARKPTR_MASK);
}

static inline uint8
markptr_mark(pg_uintptr mptr)
{
	return (mptr & MARKPTR_MASK);
}

static inline pg_uintptr
markptr_make(void *ptr, uint8 mark)
{
	AssertPointerAlignment(ptr, MPTR_ALIGN);
	return ((pg_uintptr) ptr) | (mark & MARKPTR_MASK);
}

/* ------------------------------
 * Memory reclamation placeholder
 *
 * Any concurrent data structure that requires deferred memory reclamation
 * (e.g. to avoid the ABA-problem) and uses SharRetire() mechanism for this
 * must have a RetireNode instance at the start.
 *
 * If there is a way to tell if the data is retired or still in use then
 * the memory for RetireNode might shared for some other use. E.g. it is
 * possible to use it for a marked pointer provided that the mark is not
 * equal to 0. See LazyListNode for an example.
 */

typedef pg_atomic_uintptr RetireNode;

/* ----------------
 * Concurrent lists
 *
 * The algorithm is based on the following paper:
 *
 * [2005] Steve Heller, Maurice Herlihy, Victor Luchangco, Mark Moir,
 * William N. Scherer III, and Nir Shavit
 * "A Lazy Concurrent List-Based Set Algorithm"
 *
 * The original algorithm is modified to allow a list node to be in 3
 * states:
 *  -- be in list;
 *  -- be removed from a list but still used;
 *  -- be retired and waiting for memory reclamation.
 * In the first two states two different non-zero pointer mark values
 * are used. In the last state the pointer is not marked.
 */

#define LAZY_LIST_MARK_IN		1
#define LAZY_LIST_MARK_OUT		2

typedef struct
{
	union
	{
		pg_atomic_uintptr next;
		RetireNode retire_node;
	};
	slock_t	lock;
} LazyListNode;

typedef struct
{
	LazyListNode head;
	LazyListNode tail;
} LazyList;

typedef struct
{
	LazyList *list;
	LazyListNode *pred;
	LazyListNode *curr;
} LazyListIterator;

static inline void
LazyListInit(LazyList *list)
{
	LazyListNode *head = &list->head;
	LazyListNode *tail = &list->tail;
	/* Initialize the head node. */
	pg_atomic_init_uintptr(&head->next,
						   markptr_make(tail, LAZY_LIST_MARK_IN));
	SpinLockInit(&head->lock);
	/* Initialize the tail node. */
	pg_atomic_init_uintptr(&tail->next,
						   markptr_make(NULL, LAZY_LIST_MARK_IN));
	SpinLockInit(&tail->lock);
}

static inline uint8
LazyListNodeMark(LazyListNode *node)
{
	return markptr_mark(pg_atomic_read_uintptr(&node->next));
}

static inline bool
LazyListNodeTest(LazyListNode *node, LazyList *list)
{
	pg_read_barrier();
	return LazyListNodeMark(node) == LAZY_LIST_MARK_IN;
}

static inline bool
LazyListIsTail(LazyListNode *node, LazyList *list)
{
	return node == &list->tail;
}

static inline LazyListNode *
LazyListCurrent(LazyListIterator *iter)
{
	if (LazyListIsTail(iter->curr, iter->list))
		return NULL;
	return iter->curr;
}

static inline LazyListNode *
LazyListBegin(LazyListIterator *iter, LazyList *list)
{
	iter->list = list;
	iter->pred = &list->head;
	iter->curr = markptr_ptr(pg_atomic_read_uintptr(&list->head.next));
	return LazyListCurrent(iter);
}

static inline LazyListNode *
LazyListGetNext(LazyListIterator *iter)
{
	pg_uintptr	next = pg_atomic_read_uintptr(&iter->curr->next);
	uint8		mark = markptr_mark(next);
	if (mark != LAZY_LIST_MARK_IN && mark != LAZY_LIST_MARK_OUT)
		return NULL;
	return markptr_ptr(next);
}

static inline LazyListNode *
LazyListMoveToNext(LazyListIterator *iter, LazyListNode *node)
{
	iter->pred = iter->curr;
	iter->curr = node;
	return LazyListCurrent(iter);
}

static inline LazyListNode *
LazyListNextSlow(LazyListIterator *iter)
{
	LazyListNode *save = iter->curr;
	LazyListNode *node = LazyListBegin(iter, iter->list);
	while (node != NULL && node <= save)
	{
		if ((node = LazyListGetNext(iter)) == NULL)
			node = LazyListBegin(iter, iter->list);
		else
			node = LazyListMoveToNext(iter, node);
	}
	return node;
}

static inline LazyListNode *
LazyListNext(LazyListIterator *iter)
{
	LazyListNode *node;
	Assert(!LazyListIsTail(iter->curr, iter->list));
	if ((node = LazyListGetNext(iter)) == NULL)
		return LazyListNextSlow(iter);
	return LazyListMoveToNext(iter, node);
}

static inline bool
LazyListValidate(LazyListIterator *iter)
{
	pg_uintptr	pred_next, curr_next;
	curr_next = pg_atomic_read_uintptr(&iter->curr->next);
	if (markptr_mark(curr_next) != LAZY_LIST_MARK_IN)
		return false;
	pred_next = pg_atomic_read_uintptr(&iter->pred->next);
	if (markptr_mark(pred_next) != LAZY_LIST_MARK_IN)
		return false;
	return markptr_ptr(pred_next) == iter->curr;
}

static inline void
LazyListLock(LazyListIterator *iter)
{
	SpinLockAcquire(&iter->pred->lock);
	SpinLockAcquire(&iter->curr->lock);
}

static inline void
LazyListUnlock(LazyListIterator *iter)
{
	SpinLockRelease(&iter->curr->lock);
	SpinLockRelease(&iter->pred->lock);
}

static inline void
LazyListRemoveCurr(LazyListIterator *iter)
{
	pg_uintptr	curr_next = pg_atomic_read_uintptr(&iter->curr->next);
	LazyListNode *node = markptr_ptr(curr_next);
	/* Logically remove. */
	pg_atomic_write_uintptr(&iter->curr->next,
							markptr_make(node, LAZY_LIST_MARK_OUT));
	/* Make sure the logical removal is visible before the physical. */
	pg_write_barrier();
	/* Physically remove. */
	pg_atomic_write_uintptr(&iter->pred->next,
							markptr_make(node, LAZY_LIST_MARK_IN));
}

static inline void
LazyListInsertCurr(LazyListIterator *iter, LazyListNode *node)
{
	/* Prepare for insert. */
	SpinLockInit(&node->lock);
	pg_atomic_write_uintptr(&node->next,
							markptr_make(iter->curr, LAZY_LIST_MARK_IN));
	/* Make sure the node is actually prepared before the insertion. */
	pg_write_barrier();
	/* Physically insert. */
	pg_atomic_write_uintptr(&iter->pred->next,
							markptr_make(node, LAZY_LIST_MARK_IN));
}

static inline bool
LazyListRemove(LazyList *list, LazyListNode *node)
{
	bool found;
	for (;;)
	{
		LazyListIterator iter;
		LazyListNode *curr = LazyListBegin(&iter, list);
		while (curr != NULL && curr < node)
			curr = LazyListNext(&iter);

		LazyListLock(&iter);
		if (LazyListValidate(&iter))
		{
			if ((found = (iter.curr == node)))
				LazyListRemoveCurr(&iter);
			LazyListUnlock(&iter);
			break;
		}
		LazyListUnlock(&iter);
	}
	return found;
}

static inline bool
LazyListInsert(LazyList *list, LazyListNode *node)
{
	bool found;
	for (;;)
	{
		LazyListIterator iter;
		LazyListNode *curr = LazyListBegin(&iter, list);
		while (curr != NULL && curr < node)
			curr = LazyListNext(&iter);

		LazyListLock(&iter);
		if (LazyListValidate(&iter))
		{
			if (!(found = (iter.curr == node)))
				LazyListInsertCurr(&iter, node);
			LazyListUnlock(&iter);
			break;
		}
		LazyListUnlock(&iter);
	}
	return !found;
}

#endif	/* CONCURRENCY_H */
