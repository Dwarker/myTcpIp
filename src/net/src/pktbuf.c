#include "pktbuf.h"
#include "dbg.h"
#include "mblock.h"
#include "nlocker.h"

#if 0
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
#endif

static nlocker_t locker;
static pktblk_t block_buffer[PKTBUF_BLK_CNT];
static mblock_t block_list; //将buffer建立成链表,方便管理
static pktbuf_t pktbuf_buffer[PKTBUF_BUF_CNT];
static mblock_t pktbuf_list; //将buffer建立成链表,方便管理

net_err_t pktbuf_init (void) {
    dbg_info(DBG_BUF, "init pktbuf");

    nlocker_init(&locker, NLOCKER_THREAD);
    mblock_init(&block_list, block_buffer, sizeof(pktblk_t), PKTBUF_BLK_CNT, NLOCKER_THREAD);
    mblock_init(&pktbuf_list, pktbuf_buffer, sizeof(pktbuf_t), PKTBUF_BUF_CNT, NLOCKER_THREAD);
    
    dbg_info(DBG_BUF, "init done");
    return NET_ERR_OK;
}