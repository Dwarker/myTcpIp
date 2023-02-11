#ifndef MBLOCK_H
#define MBLOCK_H

#include "nlist.h"
#include "nlocker.h"

typedef struct _mblock_t {
    nlist_t free_list;
    void *start;    //只想空虚链表头部,暂时用不到
    nlocker_t locker;//线程间争对共享资源(空虚链表)的互斥
    sys_sem_t alloc_sem;//当链表为无资源时,等待使用
}mblock_t;

net_err_t mblock_init (mblock_t *mblock, void *mem, int blk_size, 
                        int cnt, nlocker_type_t locker);

//当空闲内存耗尽,不希望线程停在这里,加上等待时间,超过这段时间即返回
void *mblock_alloc (mblock_t* block, int ms);
//返回空闲内存块数量
int mblock_free_cnt (mblock_t *block);
void mblock_free (mblock_t *mblock, void *block);
void mblock_destroy (mblock_t *mblock);

#endif