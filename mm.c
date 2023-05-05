/*
 * reference: CS:APP 9.9.12
 */
#include "mm.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
// #define DEBUG
#ifdef DEBUG
#define dbg_printf(...) printf(__VA_ARGS__)
#else
#define dbg_printf(...)
#endif

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

#define MAX(x, y) ((x) > (y) ? (x) : (y))

/* single word (4) or double word (8) alignment */
#define WSIZE 4
#define ALIGNMENT 8
#define DSIZE 8
#define CHUNKSIZE 456
#define MIN_BLK_SIZE 24
#define MAX_HEAP 0xffffffff 

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

/* the pointer to the prologue block */
static char *heap_listp = 0;

static int cnt = 0;

/* read or write a word at address p */
#define GET(p) ((p) ? *(unsigned *)(p) : 0)
#define GET_PTR(p) ((p) ? (void *)*(size_t *)(p) : 0)
#define PUT(p, val) ((p) ? *(unsigned *)(p) = (val) : 0)
#define PUT_PTR(p, ptr) ((p) ? *(size_t *)(p) = (size_t)(ptr) : 0)

/* read the size and allocated fields from address p */
#define READ_SIZE(p) (GET(p) & ~0x7)
#define READ_ALLOC(p) (GET(p) & 0x1)
#define READ_L_ALLOC(p) (GET(p) & 0x2)

/* given block ptr bp, compute address of its header, footer, prev, and next */
#define HEAD(bp) ((char *)(bp) - WSIZE)
#define PRE_BLK_F(bp) ((char *)(bp))
#define NXT_BLK_F(bp) ((bp) ? (char *)(bp) + DSIZE : (char *)0)
#define PRE_BLK_AT(bp) (GET_PTR(PRE_BLK_F(bp)))
#define NXT_BLK_AT(bp) (GET_PTR(NXT_BLK_F(bp)))
#define FOOT(bp) ((char *)(bp) + READ_SIZE(HEAD(bp)) - DSIZE)

#define L_BLK(bp) ((char *)(bp) - READ_SIZE((char *)(bp) - DSIZE))
#define R_BLK(bp) ((char *)(bp) + READ_SIZE(HEAD(bp)))

/* pack a size and allocated bit into a word */
#define PACK(size, alloc) ((size) | (alloc))

#define SEG_LIST_SIZE 7

static void *lst_blk[SEG_LIST_SIZE];

/*
 * mm_init - Called when a new trace starts.
 */
int mm_init(void) {
  if ((heap_listp = mem_sbrk(8 * WSIZE)) == (void *)-1) return -1;
  PUT(heap_listp + 1 * WSIZE, PACK(6 * WSIZE, 3)); /* prologue header */
  PUT_PTR(heap_listp + 2 * WSIZE, 0);              /* prev pointer */
  PUT_PTR(heap_listp + 4 * WSIZE, 0);              /* next pointer */
  PUT(heap_listp + 6 * WSIZE, PACK(6 * WSIZE, 3)); /* prologue footer */
  PUT(heap_listp + 7 * WSIZE, PACK(0, 3));         /* epilogue header */
  heap_listp += 2 * WSIZE;
  memset(lst_blk, 0, sizeof(lst_blk));
  dbg_printf("heap_size = %ld\n", mem_heapsize());
  return 0;
}

static inline void delete_from_list(void *bp) {
  dbg_printf("delete_from_list, bp = %p, pre = %p, nxt = %p\n", bp, PRE_BLK_AT(bp), NXT_BLK_AT(bp));
  if (!PRE_BLK_AT(bp)) {
    size_t size = READ_SIZE(HEAD(bp)), at = 0;
    for (size_t tmp = MIN_BLK_SIZE; tmp < size && at < SEG_LIST_SIZE - 1; tmp <<= 2, ++at);
    lst_blk[at] = NXT_BLK_AT(bp);
    dbg_printf("lst_blk[%ld] = %p, the nxt = %p\n", at, lst_blk[at], NXT_BLK_AT(lst_blk[at]));
  } else {
    PUT_PTR(NXT_BLK_F(PRE_BLK_AT(bp)), NXT_BLK_AT(bp));
  }
  PUT_PTR(PRE_BLK_F(NXT_BLK_AT(bp)), PRE_BLK_AT(bp));
}
static inline void add_to_list(void *bp) {
  size_t size = READ_SIZE(HEAD(bp)), at = 0;
  for (size_t tmp = MIN_BLK_SIZE; tmp < size && at < SEG_LIST_SIZE - 1; tmp <<= 2, ++at);
  dbg_printf("add_to_list, at = %ld\n", at);
  PUT_PTR(NXT_BLK_F(bp), lst_blk[at]);
  PUT_PTR(PRE_BLK_F(bp), 0);
  if (lst_blk[at]) PUT_PTR(PRE_BLK_F(lst_blk[at]), bp);
  lst_blk[at] = bp;
  dbg_printf("lst_blk[%ld] = %p\n", at, lst_blk[at]);
}

static inline void change_alloc(void *bp, size_t size, unsigned alloc) {
  PUT(HEAD(bp), PACK(size, READ_L_ALLOC(HEAD(bp)) | alloc));
  if (!alloc) PUT(FOOT(bp), PACK(size, READ_L_ALLOC(HEAD(bp)) | alloc));
  PUT(HEAD(R_BLK(bp)), PACK(READ_SIZE(HEAD(R_BLK(bp))),
                            alloc << 1 | READ_ALLOC(HEAD(R_BLK(bp)))));
}

static void *coalesce_and_add(void *bp) {
  dbg_printf("coalesce_and_add, bp = %p\n", bp);
  size_t size = READ_SIZE(HEAD(bp));
  if (!READ_L_ALLOC(HEAD(bp))) {
    dbg_printf("coalesce left, bp = %p\n", L_BLK(bp));
    size += READ_SIZE(FOOT(L_BLK(bp)));
    delete_from_list(L_BLK(bp));
    bp = L_BLK(bp);
    change_alloc(bp, size, 0);
  }
  if (!READ_ALLOC(HEAD(R_BLK(bp)))) {
    dbg_printf("coalesce right, bp = %p\n", R_BLK(bp));
    size += READ_SIZE(HEAD(R_BLK(bp)));
    delete_from_list(R_BLK(bp));
    change_alloc(bp, size, 0);
  }
  dbg_printf("coalesce size = %ld, bp = %p\n", size, bp);
  add_to_list(bp);
  return bp;
}

/*
 * place - Place block of size bytes at start of block bp (MAYBE NOT FREE)
 *     and split if remainder would be at least minimum block size.
 */
static void place(void *bp, size_t size) {
  size_t blk_size = READ_SIZE(HEAD(bp));
  unsigned is_alloc = READ_ALLOC(HEAD(bp));
  dbg_printf("place, is_alloc = %u\n", READ_ALLOC(HEAD(bp)));
  if (blk_size >= size + MIN_BLK_SIZE) { /* split */
    if (!is_alloc) delete_from_list(bp);
    change_alloc(bp, size, 1);
    change_alloc(R_BLK(bp), blk_size - size, 0);
    add_to_list(R_BLK(bp));
  } else { /* no split */
    if (!is_alloc) delete_from_list(bp);
    change_alloc(bp, blk_size, 1);
  }
}

/*
 * extend_heap - Extend heap by calling mem_sbrk and return the new block bp.
 *      Also add the new block to the free list and coalesce if necessary.
 */
static void *extend_heap(size_t size) {
  void *bp = mem_sbrk(size);
  dbg_printf("extend_heap, bp = %p\n", bp);
  if (bp == (void *)-1) return NULL;
  change_alloc(bp, size, 0);
  /* new epilogue header */
  PUT(HEAD(R_BLK(bp)), PACK(0, READ_L_ALLOC(HEAD(R_BLK(bp))) | 1));
  return coalesce_and_add(bp);
}

/*
 * malloc - Allocate a block by incrementing the brk pointer.
 *      Always allocate a block whose size is a multiple of the alignment.
 */
void *malloc(size_t size) {
  // if (size == 0) return NULL;
  ++cnt; dbg_printf("#%d malloc %ld\n", cnt, size);
  size = ALIGN(MAX(MIN_BLK_SIZE, size + WSIZE));
  void *bp = NXT_BLK_AT(heap_listp);
  dbg_printf("bp = %p\n", bp);
  for (int at = 0; at < SEG_LIST_SIZE; ++at) {
    if (MIN_BLK_SIZE << (at << 1) < (int)size || !lst_blk[at]) continue;
    for (bp = lst_blk[at]; bp; bp = NXT_BLK_AT(bp)) {/* explicit free list */
      dbg_printf("$ bp = %p\n", bp);
      if (READ_SIZE(HEAD(bp)) >= size) {
        assert(!READ_ALLOC(HEAD(bp)));
        dbg_printf("found %u, at = %d\n", READ_SIZE(HEAD(bp)), at);
        place(bp, size);
        dbg_printf("place done, bp = %p\n", bp);
        return bp;
      }
    }
  }
  dbg_printf("extend_heap %ld\n", MAX(CHUNKSIZE, size));
  /* need to extend the heap */
  bp = extend_heap(MAX(CHUNKSIZE, size));
  if (bp != NULL) place(bp, size);
  return bp;
}

/*
 * free - We don't know how to free a block.  So we ignore this call.
 *      Computers have big memories; surely it won't be a problem.
 */
void free(void *ptr) {
  ++cnt; dbg_printf("#%d free %p\n", cnt, ptr);
  if (ptr < mem_heap_lo() || ptr > mem_heap_hi()) return;
  size_t size = READ_SIZE(HEAD(ptr));
  change_alloc(ptr, size, 0);
  coalesce_and_add(ptr);
}

/*
 * realloc - Change the size of the block by mallocing a new block,
 *      copying its data, and freeing the old block.  I'm too lazy
 *      to do better.
 */
void *realloc(void *oldptr, size_t size) {
  ++cnt; dbg_printf("#%d realloc, ptr = %p, size = %lu\n", cnt, oldptr, size);
  size_t oldsize;
  void *newptr;

  /* If size == 0 then this is just free, and we return NULL. */
  if (size == 0) {
    free(oldptr);
    return 0;
  }

  /* If oldptr is NULL, then this is just malloc. */
  if (oldptr == NULL) {
    return malloc(size);
  }
  oldsize = READ_SIZE(HEAD(oldptr));
  size = ALIGN(MAX(MIN_BLK_SIZE, size + WSIZE));
  if (size <= oldsize) {
    place(oldptr, size);
    newptr = oldptr;
  } else if (!READ_ALLOC(HEAD(R_BLK(oldptr))) &&
             oldsize + READ_SIZE(HEAD(R_BLK(oldptr))) >= size) {
    delete_from_list(R_BLK(oldptr));
    size_t right_size = READ_SIZE(HEAD(R_BLK(oldptr)));
    change_alloc(oldptr, oldsize + right_size, 1);
    place(oldptr, size);
    newptr = oldptr;
  } else {
    dbg_printf("realloc %ld\n", size);
    newptr = malloc(size);
    /* If realloc() fails the original block is left untouched  */
    if (!newptr) return NULL;
    memcpy(newptr, oldptr, oldsize);
    /* Free the old block. */
    free(oldptr);
  }
  return newptr;
}

/*
 * calloc - Allocate the block and set it to zero.
 */
void *calloc(size_t nmemb, size_t size) {
  size_t bytes = nmemb * size;
  void *newptr;

  newptr = malloc(bytes);
  memset(newptr, 0, bytes);

  return newptr;
}

/*
 * mm_checkheap - There are no bugs in my code, so I don't need to check,
 *      so nah!
 */
void mm_checkheap(int verbose) {
  verbose = verbose;
  return;
}
