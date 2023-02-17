#ifndef PKTBUF_H
#define PKTBUF_H

#include <stdint.h>
#include "nlist.h"
#include "net_cfg.h"
#include "net_err.h"

typedef struct _pktblk_t {
    nlist_node_t node;
    int size;   //当前使用的大小
    uint8_t *data;
    uint8_t payload[PKTBUF_BLK_SIZE];
}pktblk_t;

typedef struct _pktbuf_t {
    int total_size;     //数据包总大小
    nlist_t blk_list;
    nlist_node_t node;  //用来链接数据包

    //数据可能是不连续的,所有逻辑上从pos位置开始
    //查找就可以了,但是实际上分布在不同的数据包中,
    //所以新增curr_blk变量指向pos位置在哪个数据包中,
    //再新增blk_offset指向逻辑上的pos位置,在curr_blk数据包的哪个位置
    int pos;//当前读取的数据位置
    pktblk_t *curr_blk;//
    uint8_t *blk_offset;
}pktbuf_t;

net_err_t pktbuf_init (void);
pktbuf_t *pktbuf_alloc (int size);
void pktbuf_free (pktbuf_t *buf);

static inline pktblk_t *pktblk_blk_next (pktblk_t *blk) {
    nlist_node_t *next = nlist_node_next(&blk->node);
    return nlist_entry(next, pktblk_t, node);
}

static inline pktblk_t *pktbuf_first_blk (pktbuf_t *buf) {
    nlist_node_t *first = nlist_first(&buf->blk_list);
    return nlist_entry(first, pktblk_t, node);
}

static inline pktblk_t *pktbuf_last_blk (pktbuf_t *buf) {
    nlist_node_t *last = nlist_last(&buf->blk_list);
    return nlist_entry(last, pktblk_t, node);
}

static int inline pktbuf_total (pktbuf_t *buf) {
    return buf->total_size;
}

//size:新增头部大小, cont:头部是否连续
net_err_t pktbuf_add_header(pktbuf_t *buf, int size, int cont);
//size:移除多大的空间
net_err_t pktbuf_remove_header(pktbuf_t *buf, int size);
//从尾部调(如果头部有空,是不管的)
net_err_t pktbuf_resize(pktbuf_t *buf, int to_size);
net_err_t pktbuf_join(pktbuf_t *dest, pktbuf_t *src);
//将不连续的数据合并成一个包
net_err_t pktbuf_set_cont(pktbuf_t *buf, int size);
//重置访问字段
void pktbuf_reset_acc(pktbuf_t *buf);
//写数据
net_err_t pktbuf_write (pktbuf_t *buf, uint8_t *src, int size);

#endif