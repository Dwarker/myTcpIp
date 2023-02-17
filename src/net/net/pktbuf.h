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

//size:新增头部大小, cont:头部是否连续
net_err_t pktbuf_add_header(pktbuf_t *buf, int size, int cont);
//size:移除多大的空间
net_err_t pktbuf_remove_header(pktbuf_t *buf, int size);
//从尾部调(如果头部有空,是不管的)
net_err_t pktbuf_resize(pktbuf_t *buf, int to_size);
net_err_t pktbuf_join(pktbuf_t *dest, pktbuf_t *src);

#endif