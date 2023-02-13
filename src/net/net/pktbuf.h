#ifndef PKTBUF_H
#define PKTBUF_H

#include <stdint.h>
#include "nlist.h"
#include "net_cfg.h"
#include "net_err.h"

typedef struct _pktblk_t {
    nlist_node_t node;
    int size;
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
#endif