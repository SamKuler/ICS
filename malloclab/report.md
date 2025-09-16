# ICS Malloc Lab Report
#### Zeng Guanyang

本实验要求实现动态内存分配的相关函数。为了在吞吐率以及峰值利用率上去的较好的效果，采用**分离空闲链表**（**Segrated Free List**）+**首次适配**的方式实现。在实现的过程中参考了书上的代码以及宏定义，并且参考了[这个网站](https://arthals.ink/blog/malloc-lab)~~（但是实际效果不是很好）~~。  
最后结果如下：
```
Results for mm malloc:
trace            name     valid  util     ops      secs   Kops
 1     amptjp-bal.rep       yes   99%    5694  0.000107  52967
 2       cccp-bal.rep       yes   99%    5848  0.000105  55748
 3    cp-decl-bal.rep       yes   99%    6648  0.000124  53656
 4       expr-bal.rep       yes   99%    5380  0.000101  53162
 5 coalescing-bal.rep       yes   97%   14400  0.000146  98698
 6     random-bal.rep       yes   96%    4800  0.000300  16016
 7    random2-bal.rep       yes   95%    4800  0.000301  15963
 8     binary-bal.rep       yes   91%   12000  0.000303  39656
 9    binary2-bal.rep       yes   81%   24000  0.000317  75758
10    realloc-bal.rep       yes   99%   14401  0.000092 156024
11   realloc2-bal.rep       yes   99%   14401  0.000061 234927
Total                             96%  112372  0.001957  57426

Score = (58 (util) + 40 (thru)) * 11/11 (testcase) = 59/100
```

### 结构
对于显示空闲链表，其中堆块的结构如下：
```
< 分配块 >
        63 ... 21 20 19 18 17 16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
        +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
头部p:  |       块大小                                                |  |  |  | A| <-- A表示是否分配
bp ---> +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                                                        |
        |                                                                        |
        .       有效载荷以及填充                                                   .
        .                                                                        .
        .                                                                        .
        +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 脚部:  |       块大小                                                |        | A|
        +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 
 
< 空闲块 >
        63 ... 21 20 19 18 17 16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
        +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
头部p:  |       块大小                                                |  |  |  | A| <-- A表示是否分配
bp ---> +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |       后继指针                                                          |
        +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |       前驱指针                                                          |
        +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                                                        |
        .       有效载荷以及填充                                                   .
        .                                                                        .
        .                                                                        .
        +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 脚部:  |       块大小                                                |        | A|
        +--+---+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

```
为了减少分配的时间，采用了分离式的方式。也就是通过`lists`数组来存储不同大小范围的空闲块，通过检索某一大小类中的空闲块，可以减少分配的时间。

### 结构操作
为了实现上述的结构并且利于使用，采用了宏定义的方式。具体如下：
```c
#define WSIZE 8 // 64位下要求malloc返回的地址16字节对齐，因此字长相当于8字节。实际可以看作是Header和Footer的大小
#define DSIZE 16 // 16字节对齐的要求

#define INITSIZE (1<<6)//初始堆大小，在mm_init中使用。
#define CHUNKSIZE (1<<12)//扩展堆大小，在extend_heap中使用。

#define PACK(size, alloc) ((size) | (alloc)) //将块大小和分配位打包到一个字中
#define GET(p) (*(unsigned long *)(p)) //读取一个字。由于是WSIZE=8，因此为unsigned long
#define PUT(p, val) (*(unsigned long *)(p) = (val)) //写入一个字
#define GET_SIZE(p) (GET(p) & ~0xF) //读取块大小。由对齐要求，块大小为16的倍数，因此低4位为0
#define GET_ALLOC(p) (GET(p) & 0x1) //读取分配位。分配位在低位，因此只需取最低位

#define HDRP(bp) ((char *)(bp) - WSIZE) //返回块的头部指针
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) //返回块的脚部指针

#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE))) //返回下一个块的指针
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE))) //返回前一个块的指针

#define NEXT_FREE(bp) (*(char **)(bp)) //返回下一个空闲块的地址。
#define PREV_FREE(bp) (*(char **)(bp + WSIZE)) //返回前一个空闲块的地址。

#define NEXT_FREE_PTR(bp) ((char *)(bp)) //返回指向下一个空闲块的指针
#define PREV_FREE_PTR(bp) ((char *)(bp + WSIZE)) //返回指向前一个空闲块的指针

#define LIST_NUM 16 //分离空闲链表的大小
static char **lists; //分离空闲链表，采用二级指针的方式

static char *heap_listp; //堆的起始地址。不包括指针数组lists

//辅助函数
static int get_list_index(size_t size)//快速得到size对应的lists的下标，由于块的大小是16的倍数，因此lists[0]对应的是小于等于16的块，lists[1]对应的是17-32的块，以此类推。
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
```

### 具体实现

#### mm_init
初始化堆，分配空间，初始化分离空闲链表。具体如下：
```c
int mm_init(void)
{
    // 首先创建空间来存储分离空闲链表项
    if ((heap_listp = mem_sbrk(LIST_NUM * WSIZE)) == (void *)-1)
        return -1;

    // 初始化每一个链表指向的空闲块为0
    lists = heap_listp;
    for (int i = 0; i < LIST_NUM; i++)
    {
        lists[i] = 0;
    }

    // 初始化堆，由于要求分配的地址是16字节对齐的，创建列表使用了16*WSIZE的空间，由于还需加上头部，因此还需一个WSIZE的空间来填充以对齐。之后创建一个初始的分配块用作边界，以及大小为0的分配块作为结尾。
    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *)-1)
        return -1;
    PUT(heap_listp, 0);                          // Padding
    PUT(heap_listp + 1 * WSIZE, PACK(DSIZE, 1)); // Prologue header
    PUT(heap_listp + 2 * WSIZE, PACK(DSIZE, 1)); // Prologue footer
    PUT(heap_listp + 3 * WSIZE, PACK(0, 1));     // Epilogue header
    heap_listp += 2 * WSIZE;                     // 16 bytes alignment
    //heap_listp指向有效载荷的起始地址

    // 开始分配初始的内存空间。这一个空间不必很大，不然会造成内存浪费
    if (extend_heap(INITSIZE) == NULL)
        return -1;
    return 0;
}
```

#### extend_heap
用于扩展堆空间。并且保证边界以及新分配的空间作为空闲块。具体如下：
```c
static void *extend_heap(size_t asize)
{
    char *bp;
    size_t size;

    // 保证对齐
    size = ALIGN(asize);

    if ((long)(bp = mem_sbrk(size)) == -1)
        return NULL;

    // 初始化新的空闲块
    PUT(HDRP(bp), PACK(size, 0));         // Free block header
    PUT(FTRP(bp), PACK(size, 0));         // Free block footer
    // 初始化新的结尾块
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); // New epilogue header

    // 尝试将新的空闲块与之前的合并。实际上也在插入到空闲列表当中。
    return coalesce(bp);
}
```

#### coalesce
用于合并空闲块，并且维护其所属的空闲链表。具体如下：
```c
static void *coalesce(void *bp)
{
    // 获取前后块的分配情况
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    // 获取当前块的大小
    size_t size = GET_SIZE(HDRP(bp));

    if (prev_alloc && next_alloc)
    { // Case 1 两边都分配了，则直接插入到空闲链表中
        freelist_insert(bp, size);
        return bp;
    }
    else if (prev_alloc && !next_alloc)
    { // Case 2 后面的块未分配，合并后插入到空闲链表中
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        freelist_remove(NEXT_BLKP(bp));//从空闲链表中移除后面的块
        PUT(HDRP(bp), PACK(size, 0));//更新头部
        PUT(FTRP(bp), PACK(size, 0));//更新脚部
    }
    else if (!prev_alloc && next_alloc)
    { // Case 3 前面的块未分配，合并后插入到空闲链表中
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        freelist_remove(PREV_BLKP(bp));//从空闲链表中移除前面的块
        PUT(FTRP(bp), PACK(size, 0));//更新脚部
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));//更新头部
        bp = PREV_BLKP(bp);//返回前面的块。因为当前bp的位置已经失效
    }
    else
    { // Case 4 前后块都未分配，合并后插入到空闲链表中
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));
        freelist_remove(PREV_BLKP(bp));
        freelist_remove(NEXT_BLKP(bp));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }
    SET_NEXT_FREE(bp, NULL);//设置前后指针指向的空闲块为NULL，再插入到空闲链表中
    SET_PREV_FREE(bp, NULL);
    freelist_insert(bp, size);
    return bp;
}
```

#### freelist_insert
用于将空闲块插入到空闲链表中。具体如下：
```c
static void freelist_insert(void *bp, size_t size)
{
    // 获取空闲块的大小，以及对应的空闲链表的下标
    int index = get_list_index(GET_SIZE(HDRP(bp)));
    char *next = lists[index];//开始查找的空闲块内存地址
    char *prev = NULL;

    //按照大小顺序插入（插入排序）。获得插入的位置
    while (next != NULL && GET_SIZE(HDRP(next)) < size)
    {
        prev = next;
        next = NEXT_FREE(next);
    }
    // 在prev和next之间插入
    // NEXT_FREE_PTR/PREV_FREE_PTR为该块所储存的前后内存块的地址。
    if (next != NULL)
    {
        if (prev != NULL)
        {
            PUT(NEXT_FREE_PTR(prev), bp);
            PUT(PREV_FREE_PTR(bp), prev);
        }
        else
        {//如果prev为空，说明是第一个块，直接更新lists
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
        {//如果prev为空，说明是第一个块，直接更新lists
            lists[index] = bp;
            PUT(PREV_FREE_PTR(bp), NULL);
        }
        //next为空，说明是最后一个块，直接更新next为空
        PUT(NEXT_FREE_PTR(bp), NULL);
    }
    return;
}
```

#### freelist_remove
用于将空闲块从空闲链表中移除。具体如下：
```c
static void freelist_remove(void *bp)
{
    // 获取空闲块的大小，以及对应的空闲链表的下标
    int index = get_list_index(GET_SIZE(HDRP(bp)));
    // 尝试获取前后块的地址
    char *prev = PREV_FREE(bp);
    char *next = NEXT_FREE(bp);

    // 更新对应位置的前后指针。
    if (next != NULL)
    {
        if (prev != NULL)
        {
            PUT(NEXT_FREE_PTR(prev), next);
            PUT(PREV_FREE_PTR(next), prev);
        }
        else
        {//如果prev为空，说明是第一个块，直接更新lists
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
        {//如果prev为空，说明是第一个块，直接更新lists
            lists[index] = NULL;
        }
    }
    return;
}
```

在初始化后，分配/释放/再分配内存。

#### mm_malloc
用于分配内存。具体如下：
```c
void *mm_malloc(size_t size)
{
    size_t asize;      // 块大小。要根据size对齐。
    size_t extendsize; // 临时变量，要扩展堆的大小（如果需要）
    char *bp;

    // 忽略无意义请求
    if (size == 0)
        return NULL;

    // 如果当前的堆未初始化，那么heap_listp为0。据此可以初始化堆。
    if (heap_listp == 0)
        mm_init();

    // 根据对齐要求，计算块大小
    if (size <= DSIZE)
    {
        asize = 2 * DSIZE;
    }
    else
    {
        asize = ALIGN(size + DSIZE);
    }

    // 搜索合适的空闲块，并且放置
    if ((bp = find_fit(asize)) != NULL)
    {

        return place(bp, asize);
    }

    // 如果没有合适的空闲块，那么扩展堆的大小，并且放置
    extendsize = MAX(asize, CHUNKSIZE);
    if ((bp = extend_heap(extendsize)) == NULL)
        return NULL;

    return place(bp, asize);
}
```

#### find_fit
用于寻找合适的空闲块来分配，采用首次匹配的方式。具体如下：
```c
static void *find_fit(size_t asize)
{
    // 要分配的位置不会比这个更小
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
            //循链表访问每一个空闲块，直到找到合适的大小插入
            bp = NEXT_FREE(bp);
        }
    }
    // 没有找到合适的空闲块
    return NULL;
}
```

#### place
用于放置分配的内存。具体如下：
```c
static void *place(void *bp, size_t asize)// asize为要分配的大小
{
    // 当前的空闲块的大小
    size_t csize = GET_SIZE(HDRP(bp));
    // 未分配。将其从空闲列表中移除。
    if (GET_ALLOC(HDRP(bp)) == 0)
    {
        freelist_remove(bp);
    }
    if ((csize - asize) >= (2 * DSIZE)) // 如果还有空闲，能够放下一个空闲块，则进行划分
    {
        if (asize > 100)//根据asize的不同将分配块放到不同的位置。对于大块放置在后，在realloc的时候能够大概率通过extend_heap来快速扩容以提高内存利用率。
        //同时大小块的位置的错开能够使得空闲块能够前后相邻，提高能够合并的数量，减小内存碎片。
        {
            //在前面划分空闲块
            PUT(HDRP(bp), PACK(csize - asize, 0));
            PUT(FTRP(bp), PACK(csize - asize, 0));
            //在后面划分分配块
            PUT(HDRP(NEXT_BLKP(bp)), PACK(asize, 1));
            PUT(FTRP(NEXT_BLKP(bp)), PACK(asize, 1));
            freelist_insert(bp, csize - asize);
            return NEXT_BLKP(bp);
        }
        else
        {
            //在前面划分分配块
            PUT(HDRP(bp), PACK(asize, 1));
            PUT(FTRP(bp), PACK(asize, 1));
            //在后面划分空闲块
            PUT(HDRP(NEXT_BLKP(bp)), PACK(csize - asize, 0));
            PUT(FTRP(NEXT_BLKP(bp)), PACK(csize - asize, 0));
            //尝试和之后的块合并，毕竟划分出来的空闲块比较小（csize由asize接近的2的整次幂决定，随asize增大二者差值增大，此时合并可以减小内存碎片）
            coalesce(NEXT_BLKP(bp));
        }
    }
    else
    {
        //不进行划分
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
    return bp;//返回分配的内存地址
}
```

#### mm_free
用于释放内存。具体如下：
```c
void mm_free(void *ptr)
{
    if (!ptr)
        return;
    //标志为空闲块
    size_t size = GET_SIZE(HDRP(ptr));
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    //合并空闲块
    coalesce(ptr);
    return;
}
```

#### mm_realloc
用于对mm_malloc的再分配。具体如下：
```c
void *mm_realloc(void *bp, size_t size)
{
    //如果是空，则调用malloc
    if (bp == NULL)
        return mm_malloc(size);
    //如果重新分配为0，则释放地址。
    if (size == 0)
    {
        mm_free(bp);
        return NULL;
    }

    //再分配
    char *new_ptr = bp;// 新分配的地址
    size_t oldsz = GET_SIZE(HDRP(bp));//原地址的块大小
    size_t newsz = size; // 新的块大小

    //新块大小更新以地址对齐
    if (newsz <= DSIZE)
        newsz = 2 * DSIZE;
    else
        newsz = ALIGN(size + DSIZE);

    //如果大小块大小不变，则不需要重新分配空间。
    if (oldsz == newsz)
        return new_ptr;

    // 现在需要重新分配空间
    // 需要查询前后块的分配状态，尽量通过合并后面的空闲块或者通过extend_heap来减小memcpy的调用以及减少内存碎片。
    size_t prev_alloc = GET_ALLOC(HDRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t nextsz = GET_SIZE(HDRP(NEXT_BLKP(bp)));
    // 后面的块是空闲的，并且和当前块合并后满足新的大小要求
    if (prev_alloc && !next_alloc && nextsz + oldsz >= newsz)
    {
        size_t csize = oldsz + nextsz;
        //删除后面的空闲块，将这两个块合并来分配
        freelist_remove(NEXT_BLKP(bp));
        //数据不用动，只用改变块大小
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
        return bp;
    }
    else if (nextsz == 0 && newsz > oldsz) //后面没有块了。此时可以通过调整堆大小来适应新的空间要求。
    {
        //要扩展的堆大小
        size_t extd = newsz - oldsz;
        if (mem_sbrk(extd) == (void *)-1)
            return NULL;
        //数据不用动，只用改变块大小
        PUT(HDRP(bp), PACK(oldsz + extd, 1));
        PUT(FTRP(bp), PACK(oldsz + extd, 1));
        PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));
    }
    else
    {
        //这个时候通过分配新的块的方式来满足新的大小要求。
        new_ptr = mm_malloc(size);
        if (new_ptr == NULL)
            return NULL;
        //拷贝数据
        memcpy(new_ptr, bp, MIN(oldsz, size));
        mm_free(bp);
    }
    return new_ptr;
}
```