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
#define DEBUG
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
#define CHUNKSIZE (1 << 12)
#define MIN_BLK_SIZE 24

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define SIZE_PTR(p) ((size_t *)(((char *)(p)) - SIZE_T_SIZE))

/* the pointer to the prologue block */
static char *heap_listp = 0;

/* read or write a word at address p */
#define GET(p) ((p) ? *(unsigned int *)(p) : 0)
#define PUT(p, val) ((p) ? *(unsigned int *)(p) = (val) : 0)
#define PUT_PTR(p, ptr) ((p) ? *(size_t *)(p) = (size_t)(ptr) : 0)

/* read the size and allocated fields from address p */
#define READ_SIZE(p) (GET(p) & ~0x7)
#define READ_ALLOC(p) (GET(p) & 0x1)

/* given block ptr bp, compute address of its header, footer, prev, and next */
#define HEAD(bp) ((char *)(bp) - WSIZE)
#define PRE_BLK(bp) ((char *)(bp))
#define NXT_BLK(bp) ((bp) ? (char *)(bp) + DSIZE : (char *)0)
#define FOOT(bp) ((char *)(bp) + READ_SIZE(HEAD(bp)) - DSIZE)

#define L_BLK(bp) ((char *)(bp) - READ_SIZE((char *)(bp) - DSIZE))
#define R_BLK(bp) ((char *)(bp) + READ_SIZE(HEAD(bp)))

/* pack a size and allocated bit into a word */
#define PACK(size, alloc) ((size) | (alloc))

/*
 * mm_init - Called when a new trace starts.
 */
int mm_init(void) {
  if ((heap_listp = mem_sbrk(8 * WSIZE)) == (void *)-1) return -1;
  PUT(heap_listp + 1 * WSIZE, PACK(6 * WSIZE, 1)); /* prologue header */
  PUT_PTR(heap_listp + 2 * WSIZE, 0);              /* prev pointer */
  PUT_PTR(heap_listp + 4 * WSIZE, 0);              /* next pointer */
  PUT(heap_listp + 6 * WSIZE, PACK(6 * WSIZE, 1)); /* prologue footer */
  PUT(heap_listp + 7 * WSIZE, PACK(0, 1));         /* epilogue header */
  heap_listp += 2 * WSIZE;
  return 0;
}

static void delete_from_list(void *bp) {
  PUT_PTR(NXT_BLK(PRE_BLK(bp)), NXT_BLK(bp));
  PUT_PTR(PRE_BLK(NXT_BLK(bp)), PRE_BLK(bp));
}
static void add_to_list(void *bp) {
  void *last_blk = NXT_BLK(heap_listp);
  PUT_PTR(PRE_BLK(last_blk), bp);
  PUT_PTR(NXT_BLK(bp), last_blk);
  PUT_PTR(PRE_BLK(bp), heap_listp);
  PUT_PTR(NXT_BLK(heap_listp), bp);
}

static void *coalesce_and_add(void *bp) {
  size_t size = READ_SIZE(HEAD(bp));
  if (!READ_ALLOC(FOOT(L_BLK(bp)))) {
    size += READ_SIZE(FOOT(L_BLK(bp)));
    delete_from_list(L_BLK(bp));
    bp = L_BLK(bp);
    PUT(HEAD(bp), PACK(size, 0));
    PUT(FOOT(bp), PACK(size, 0));
  }
  if (!READ_ALLOC(HEAD(R_BLK(bp)))) {
    size += READ_SIZE(HEAD(R_BLK(bp)));
    delete_from_list(R_BLK(bp));
    PUT(HEAD(bp), PACK(size, 0));
    PUT(FOOT(bp), PACK(size, 0));
  }
  add_to_list(bp);
  return bp;
}

/*
 * place - Place block of size bytes at start of block bp (MAYBE NOT FREE)
 *         and split if remainder would be at least minimum block size
 */
static void place(void *bp, size_t size) {
  size_t blk_size = READ_SIZE(HEAD(bp));
  if (!READ_ALLOC(HEAD(bp))) delete_from_list(bp);
  if (blk_size >= size + MIN_BLK_SIZE) { /* split */
    PUT(HEAD(bp), PACK(size, 1));
    PUT(FOOT(bp), PACK(size, 1));
    PUT(HEAD(R_BLK(bp)), PACK(blk_size - size, 0));
    PUT(FOOT(R_BLK(bp)), PACK(blk_size - size, 0));
    add_to_list(R_BLK(bp));
  } else { /* no split */
    PUT(HEAD(bp), PACK(blk_size, 1));
    PUT(FOOT(bp), PACK(blk_size, 1));
  }
}

/*
 * extend_heap -
 *
 */
static void *extend_heap(size_t size) {
  void *bp = mem_sbrk(size);
  if ((int)bp == -1) return NULL;
  PUT(HEAD(bp), PACK(size, 0));
  PUT(FOOT(bp), PACK(size, 0));
  PUT(HEAD(R_BLK(bp)), PACK(0, 1)); /* new epilogue header */
  return coalesce_and_add(bp);
}

/*
 * malloc - Allocate a block by incrementing the brk pointer.
 *      Always allocate a block whose size is a multiple of the alignment.
 */
void *malloc(size_t size) {
  if (size == 0) return NULL;
  size = ALIGN(size + 2 * WSIZE);
  char *bp = NXT_BLK(heap_listp);
  for (; bp; bp = NXT_BLK(bp)) /* explicit free list */
    if (READ_SIZE(HEAD(bp)) >= size) {
      place(bp, size);
      return bp;
    }
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
  size_t size = READ_SIZE(HEAD(ptr));
  PUT(HEAD(ptr), PACK(size, 0));
  PUT(FOOT(ptr), PACK(size, 0));
  coalesce_and_add(ptr);
}

/*
 * realloc - Change the size of the block by mallocing a new block,
 *      copying its data, and freeing the old block.  I'm too lazy
 *      to do better.
 */
void *realloc(void *oldptr, size_t size) {
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
  if (size + MIN_BLK_SIZE <= oldsize) {
    PUT(HEAD(oldptr), PACK(size, 1));
    PUT(FOOT(oldptr), PACK(size, 1));
    PUT(HEAD(R_BLK(oldptr)), PACK(oldsize - size, 0));
    PUT(FOOT(R_BLK(oldptr)), PACK(oldsize - size, 0));
    coalesce_and_add(R_BLK(oldptr));
    newptr = oldptr;
  } else if (!READ_ALLOC(HEAD(R_BLK(oldptr))) &&
             oldsize + READ_SIZE(HEAD(R_BLK(oldptr))) >= size) {
    delete_from_list(R_BLK(oldptr));
    size_t right_size = READ_SIZE(HEAD(R_BLK(oldptr)));
    PUT(HEAD(oldptr), PACK(oldsize + right_size, 1));
    PUT(FOOT(oldptr), PACK(oldsize + right_size, 1));
    place(oldptr, size);
    newptr = oldptr;
  } else {
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
  /*Get gcc to be quiet. */
  verbose = verbose;
}
