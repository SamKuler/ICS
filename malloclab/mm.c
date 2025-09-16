/*
 * mm.c - Using Segragated Free List.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memlib.h"
#include "mm.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "Zeng",
    /* First member's full name */
    "Zeng Guan Yang",
    /* First member's email address */
    "zenggy23@mails.tsinghua.edu.cn",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""};

/* 16 bytes alignment */
#define ALIGNMENT 16

/* Rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))

// Word and double word size
#define WSIZE 8  // Word size (header/footer size)
#define DSIZE 16 // Double word size (alignment requirement)

// Init heap by this amout
#define INITSIZE (1 << 6)
// Extend heap by this amount
#define CHUNKSIZE (1 << 12)

// Internal helper definitions

#define PACK(size, alloc) ((size) | (alloc))        // Pack the size and allocation status into a word
#define GET_SIZE(p) (*(unsigned long *)(p) & ~0xF)  // Get the size of the block, ignoring the lowest 4 bits
#define GET_ALLOC(p) (*(unsigned long *)(p) & 0x1)  // Get the allocation status of the block
#define PUT(p, val) (*(unsigned long *)(p) = (val)) // Write a value to the header/footer
#define GET(p) (*(unsigned long *)(p))              // Get a value from the header/footer

#define HDRP(bp) ((char *)(bp) - WSIZE)                      // Get the header of the block
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) // Get the footer of the block

#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE((char *)(bp) - WSIZE)) // Get the next block
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE)) // Get the previous block

#define NEXT_FREE_PTR(bp) ((char *)(bp))                 // Get the next free block pointer
#define PREV_FREE_PTR(bp) ((char *)((char *)bp + WSIZE)) // Get the previous free block pointer

#define NEXT_FREE(bp) (*(char **)(bp))                 // Get the next free block (access)
#define PREV_FREE(bp) (*(char **)((char *)bp + WSIZE)) // Get the previous free block (access)

#define SET_NEXT_FREE(bp, val) (*(unsigned long *)((char *)bp) = (unsigned long)(val))    // Set the next free block pointer
#define SET_PREV_FREE(bp, val) (*(unsigned long *)((char *)bp + WSIZE) = (unsigned)(val)) // Set the previous free block pointer

// About Segregated Free List
#define LIST_NUM 16
static char **lists; // Segregated free lists

// List management functions
static int get_list_index(size_t size);             // return the index of the list that the block belongs to
static void freelist_insert(void *bp, size_t size); // insert free block into the free list
static void freelist_remove(void *bp);              // remove free block from the free list

// Heap
static char *heap_listp; // Heap start pointer
// Heap management functions
static void *extend_heap(size_t asize);
static void *coalesce(void *bp);
static void *find_fit(size_t asize);
static void *place(void *bp, size_t asize);

// Debugger
#define __DEBUG__ 0

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
#if __DEBUG__
    printf("-----mm_init-----\n");
#endif
    // Create the initial empty heap
    if ((heap_listp = mem_sbrk(LIST_NUM * WSIZE)) == (void *)-1)
        return -1;

    // Initialize the free lists
    lists = heap_listp;
    for (int i = 0; i < LIST_NUM; i++)
    {
        lists[i] = 0;
    }

    // Initialize the heap
    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *)-1)
        return -1;
    PUT(heap_listp, 0);                          // Padding
    PUT(heap_listp + 1 * WSIZE, PACK(DSIZE, 1)); // Prologue header
    PUT(heap_listp + 2 * WSIZE, PACK(DSIZE, 1)); // Prologue footer
    PUT(heap_listp + 3 * WSIZE, PACK(0, 1));     // Epilogue header
    heap_listp += 2 * WSIZE;                     // 16 bytes alignment

    // Extend the empty heap with a free block of CHUNKSIZE bytes
    if (extend_heap(INITSIZE) == NULL)
        return -1;
    return 0;
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 *
 * Based on CSAPP Chapter 9.9.12
 */
void *mm_malloc(size_t size)
{
#if __DEBUG__
    printf("-----mm_malloc-----\n");
#endif

    size_t asize;      // Adjusted block size
    size_t extendsize; // Amount to extend heap if no fit
    char *bp;

    // Ignore spurious requests
    if (size == 0)
        return NULL;

    // Initialize heap if it isn't initialized
    if (heap_listp == 0)
        mm_init();

    // Adjust block size to include overhead and alignment reqs
    if (size <= DSIZE)
    {
        asize = 2 * DSIZE;
    }
    else
    {
        asize = ALIGN(size + DSIZE);
    }

    // Search the free list for a fit
    if ((bp = find_fit(asize)) != NULL)
    {

        return place(bp, asize);
    }

    // No fit found. Get more memory and place the block
    extendsize = MAX(asize, CHUNKSIZE);
    if ((bp = extend_heap(extendsize)) == NULL)
        return NULL;

    return place(bp, asize);
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
#if __DEBUG__
    printf("-----mm_free-----\n");
#endif
    if (!ptr)
        return;
    size_t size = GET_SIZE(HDRP(ptr));
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    coalesce(ptr);
    return;
}

/*
 * mm_realloc - reallocate a block with the new size.
 */
void *mm_realloc(void *bp, size_t size)
{
#if __DEBUG__
    printf("-----mm_realloc-----\n");
#endif
    if (bp == NULL)
        return mm_malloc(size);
    if (size == 0)
    {
        mm_free(bp);
        return NULL;
    }

    char *new_ptr = bp; // New allocated pointer
    size_t oldsz = GET_SIZE(HDRP(bp));
    size_t newsz = size; // New block size

    if (newsz <= DSIZE)
        newsz = 2 * DSIZE;
    else
        newsz = ALIGN(size + DSIZE);

    if (oldsz == newsz)
        return new_ptr;

    // Now realloc
    size_t prev_alloc = GET_ALLOC(HDRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t nextsz = GET_SIZE(HDRP(NEXT_BLKP(bp)));
    // Combine the currrent block and the next free block
    if (prev_alloc && !next_alloc && nextsz + oldsz >= newsz)
    {
        size_t csize = oldsz + nextsz;
        freelist_remove(NEXT_BLKP(bp));
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
        return bp;
    }
    else if (nextsz == 0 && newsz > oldsz) // At the epilogue block
    {
        size_t extd = newsz - oldsz;
        if (mem_sbrk(extd) == (void *)-1)
            return NULL;
        PUT(HDRP(bp), PACK(oldsz + extd, 1));
        PUT(FTRP(bp), PACK(oldsz + extd, 1));
        PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));
    }
    else
    {
        new_ptr = mm_malloc(size);
        if (new_ptr == NULL)
            return NULL;
        memcpy(new_ptr, bp, MIN(oldsz, size));
        mm_free(bp);
    }
    return new_ptr;
}

static int get_list_index(size_t size)
{
    // Rapid calculation of floor(log2(size))
    float fsize = (float)size;
    int exp = (*((unsigned *)&fsize) >> 23) & 0xFF;
    exp -= 0x7F;
    if (*((int *)&fsize) & 0x7FFFFF)
        exp++;
    if (exp <= 4)
        return 0;
    if (exp >= LIST_NUM + 4)
        return LIST_NUM - 1;
    return exp - 4;
}

static void *extend_heap(size_t asize)
{
#if __DEBUG__
    printf("-----extend_heap-----\n");
#endif
    char *bp;
    size_t size;

    // Allocate an even number of words to maintain alignment
    size = ALIGN(asize);

    if ((long)(bp = mem_sbrk(size)) == -1)
        return NULL;

    // Initialize free block header/footer and the epilogue header
    PUT(HDRP(bp), PACK(size, 0));         // Free block header
    PUT(FTRP(bp), PACK(size, 0));         // Free block footer
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); // New epilogue header

    // Coalesce if the previous block was free
    return coalesce(bp);
}

static void *coalesce(void *bp)
{
#if __DEBUG__
    printf("-----coalesce-----\n");
#endif
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));

    if (prev_alloc && next_alloc)
    { // Case 1
#if __DEBUG__
        printf("Case 1\n");
#endif
        freelist_insert(bp, size);
        return bp;
    }
    else if (prev_alloc && !next_alloc)
    { // Case 2
#if __DEBUG__
        printf("Case 2\n");
#endif
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        freelist_remove(NEXT_BLKP(bp));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }
    else if (!prev_alloc && next_alloc)
    { // Case 3
#if __DEBUG__
        printf("Case 3\n");
#endif
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        freelist_remove(PREV_BLKP(bp));
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }
    else
    { // Case 4
#if __DEBUG__
        printf("Case 4\n");
        printf("prev: %p\n", PREV_BLKP(bp));
        printf("next: %p\n", NEXT_BLKP(bp));
#endif
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));
        freelist_remove(PREV_BLKP(bp));
        freelist_remove(NEXT_BLKP(bp));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }
    SET_NEXT_FREE(bp, NULL);
    SET_PREV_FREE(bp, NULL);
    freelist_insert(bp, size);
    return bp;
}

static void *find_fit(size_t asize)
{
    int index = get_list_index(asize);
    char *bp;
    for (int i = index; i < LIST_NUM; i++)
    {
        bp = lists[i];
        while (bp != 0)
        {
            if (GET_SIZE(HDRP(bp)) >= asize)
            {
                return bp;
            }
            bp = NEXT_FREE(bp);
        }
    }
    return NULL;
}

static void *place(void *bp, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(bp));
    if (GET_ALLOC(HDRP(bp)) == 0)
    {
        freelist_remove(bp);
    }
    if ((csize - asize) >= (2 * DSIZE)) // split the block
    {
        if (asize > 100)
        {
            PUT(HDRP(bp), PACK(csize - asize, 0));
            PUT(FTRP(bp), PACK(csize - asize, 0));
            PUT(HDRP(NEXT_BLKP(bp)), PACK(asize, 1));
            PUT(FTRP(NEXT_BLKP(bp)), PACK(asize, 1));
            freelist_insert(bp, csize - asize);
            return NEXT_BLKP(bp);
        }
        else
        {
            PUT(HDRP(bp), PACK(asize, 1));
            PUT(FTRP(bp), PACK(asize, 1));
            PUT(HDRP(NEXT_BLKP(bp)), PACK(csize - asize, 0));
            PUT(FTRP(NEXT_BLKP(bp)), PACK(csize - asize, 0));
            coalesce(NEXT_BLKP(bp));
        }
    }
    else
    {
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
    return bp;
}

static void freelist_insert(void *bp, size_t size)
{
#if __DEBUG__
    printf("-----freelist_insert begin-----\n");
    for (int i = 0; i < LIST_NUM; i++)
    {
        printf("Id: %d list at %p: ", i, &lists[i]);
        char *f = lists[i];
        while (f)
        {
            printf("-> %p ", f);
            f = NEXT_FREE(f);
        }
        printf("\n");
    }
#endif

    int index = get_list_index(GET_SIZE(HDRP(bp)));
    char *next = lists[index];
    char *prev = NULL;

#if __DEBUG__
    printf("bp: %p\n", bp);
    printf("next: %p\n", next);
    printf("prev: %p\n", prev);
#endif
    while (next != NULL && GET_SIZE(HDRP(next)) < size)
    {
        prev = next;
        next = NEXT_FREE(next);
    }
    // Insert between prev and next.
    if (next != NULL)
    {
        if (prev != NULL)
        {
            PUT(NEXT_FREE_PTR(prev), bp);
            PUT(PREV_FREE_PTR(bp), prev);
        }
        else
        {
            lists[index] = bp;
            PUT(PREV_FREE_PTR(bp), NULL);
        }
        PUT(NEXT_FREE_PTR(bp), next);
        PUT(PREV_FREE_PTR(next), bp);
    }
    else
    {
        if (prev != NULL)
        {
            PUT(NEXT_FREE_PTR(prev), bp);
            PUT(PREV_FREE_PTR(bp), prev);
        }
        else
        {
            lists[index] = bp;
            PUT(PREV_FREE_PTR(bp), NULL);
        }
        PUT(NEXT_FREE_PTR(bp), NULL);
    }
#if __DEBUG__
    printf("-----freelist_insert end-----\n");
    for (int i = 0; i < LIST_NUM; i++)
    {
        printf("Id: %d list at %p: ", i, &lists[i]);
        char *f = lists[i];
        while (f)
        {
            printf("-> %p ", f);
            f = NEXT_FREE(f);
        }
        printf("\n");
    }
#endif
    return;
}

static void freelist_remove(void *bp)
{
#if __DEBUG__
    printf("-----freelist_remove begin-----\n");
    // now lists
    for (int i = 0; i < LIST_NUM; i++)
    {
        printf("Id: %d list at %p: ", i, &lists[i]);
        char *f = lists[i];
        while (f)
        {
            printf("-> %p ", f);
            f = NEXT_FREE(f);
        }
        printf("\n");
    }
#endif

    int index = get_list_index(GET_SIZE(HDRP(bp)));
    char *prev = PREV_FREE(bp);
    char *next = NEXT_FREE(bp);
#if __DEBUG__
    printf("bp: %p\n", bp);
    printf("next: %p\n", next);
    printf("prev: %p\n", prev);
#endif

    if (next != NULL)
    {
        if (prev != NULL)
        {
            PUT(NEXT_FREE_PTR(prev), next);
            PUT(PREV_FREE_PTR(next), prev);
        }
        else
        {
            lists[index] = next;
            PUT(PREV_FREE_PTR(next), NULL);
        }
    }
    else
    {
        if (prev != NULL)
        {
            PUT(NEXT_FREE_PTR(prev), NULL);
        }
        else
        {
            lists[index] = NULL;
        }
    }
#if __DEBUG__
    printf("-----freelist_remove end-----\n");
    // now lists
    for (int i = 0; i < LIST_NUM; i++)
    {
        printf("Id: %d list at %p: ", i, &lists[i]);
        char *f = lists[i];
        while (f)
        {
            printf("-> %p ", f);
            f = NEXT_FREE(f);
        }
        printf("\n");
    }
#endif
    return;
}