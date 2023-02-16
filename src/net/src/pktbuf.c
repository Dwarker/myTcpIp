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

static inline int curr_blk_tail_free (pktblk_t *blk) {
    return (int)((blk->payload + PKTBUF_BLK_SIZE) - (blk->data + blk->size));
}

static nlocker_t locker;
static pktblk_t block_buffer[PKTBUF_BLK_CNT];
static mblock_t block_list; //将buffer建立成链表,方便管理
static pktbuf_t pktbuf_buffer[PKTBUF_BUF_CNT];
static mblock_t pktbuf_list; //将buffer建立成链表,方便管理

#if DBG_DISP_ENABLED(DBG_BUF)
static void display_check_buf (pktbuf_t *buf) {
    if (!buf) {
        dbg_error(DBG_BUF, "invalid buf, buf == 0");
        return;
    }

    plat_printf("check buf %p: size %d\n", buf, buf->total_size);
    pktblk_t *curr;
    int index = 0, total_size = 0;
    for (curr = pktbuf_first_blk(buf); curr; curr = pktblk_blk_next(curr)) {
        plat_printf("%d: ", index++);

        if ((curr->data < curr->payload) 
                || (curr->data >= curr->payload + PKTBUF_BLK_SIZE)) {
            dbg_error(DBG_BUF, "bad block data.");
            return;
        }

        int pre_size = (int)(curr->data - curr->payload);
        plat_printf("pre: %d b, ", pre_size);

        int used_size = curr->size;
        plat_printf("used: %d b, ", used_size);

        int free_size = curr_blk_tail_free(curr);
        plat_printf("free: %d b, \n", free_size);

        int blk_total = pre_size + used_size + free_size;
        if (blk_total != PKTBUF_BLK_SIZE) {
            dbg_error(DBG_BUF, "bad block size: %d != %d", 
                        blk_total, PKTBUF_BLK_SIZE);
        }

        total_size += used_size;
    }

    if (total_size != buf->total_size) {
        dbg_error(DBG_BUF, "bad buf size: %d != %d", total_size, buf->total_size);
    }
}
#else
#define display_check_buf(buf)
#endif

net_err_t pktbuf_init (void) {
    dbg_info(DBG_BUF, "init pktbuf");

    nlocker_init(&locker, NLOCKER_THREAD);
    mblock_init(&block_list, block_buffer, sizeof(pktblk_t), PKTBUF_BLK_CNT, NLOCKER_THREAD);
    mblock_init(&pktbuf_list, pktbuf_buffer, sizeof(pktbuf_t), PKTBUF_BUF_CNT, NLOCKER_THREAD);
    
    dbg_info(DBG_BUF, "init done");
    return NET_ERR_OK;
}

static pktblk_t *pktblock_alloc (void) {
    //arm中可能会被中断调用,所以不能用阻塞,这里传-1
    pktblk_t *block = mblock_alloc(&block_list, -1);
    if (block) {
        block->size = 0;
        block->data = (uint8_t *)0;
        nlist_node_init(&block->node);
    }
    return block;
}

static void pktblock_free (pktblk_t *block) {
    mblock_free(&block_list, block);
}

static void pktblock_free_list (pktblk_t* first) {
    while (first) {
        pktblk_t *next_block = pktblk_blk_next(first);
        pktblock_free(first);
        first = next_block;
    }
}

//0:尾插法, 1:头插法
static pktblk_t *pktblock_alloc_list (int size, int add_front) {
    pktblk_t *first_block = (pktblk_t *)0;//返回给上层使用
    pktblk_t *pre_block = (pktblk_t *)0;//指向上一次插入的块,方便后续插入

    while (size) {
        pktblk_t *new_block = pktblock_alloc();
        if (!new_block) {
            dbg_error(DBG_BUF, "no buffer for alloc(%d)", size);
            //前面已有部分分配,此时若分配失败,则已分配部分释放掉

            return (pktblk_t *)0;
        }

        int cur_size = 0;
        if (add_front) {
            cur_size = size > PKTBUF_BLK_SIZE ? PKTBUF_BLK_SIZE : size;
            new_block->size = cur_size;
            new_block->data = new_block->payload + PKTBUF_BLK_SIZE - cur_size;
            if (first_block) {
                nlist_node_set_next(&new_block->node, &first_block->node);
            }
            first_block = new_block;
        } else {
            if (!first_block) {
                first_block = new_block;
            }

            cur_size = size > PKTBUF_BLK_SIZE ? PKTBUF_BLK_SIZE : size;
            new_block->size = cur_size;
            new_block->data = new_block->payload;
            //插入链表
            if (pre_block) {
                nlist_node_set_next(&pre_block->node, &new_block->node);
            }
        }

        size -= cur_size;
        pre_block = new_block;
    }

    return first_block;
}

static void pktbuf_insert_blk_list(pktbuf_t *buf, pktblk_t *first_blk, int add_list) {
    //尾部插入
    if (add_list) {
        while (first_blk) {
            pktblk_t *next_blk = pktblk_blk_next(first_blk);
            nlist_insert_last(&buf->blk_list, &first_blk->node);
            buf->total_size += first_blk->size;
            first_blk = next_blk;
        }
    } else {
        pktblk_t *pre = (pktblk_t *)0;
        
        while (first_blk) {
            pktblk_t* next_blk = pktblk_blk_next(first_blk);
            if (pre) {
                nlist_insert_after(&buf->blk_list, &pre->node, &first_blk->node);
            } else {
                nlist_insert_fist(&buf->blk_list, &first_blk->node);
            }

            buf->total_size += first_blk->size;
            pre = first_blk;
            first_blk = next_blk;
        }
    }
}
pktbuf_t *pktbuf_alloc (int size) {
    //pktblock_alloc_list(size, 0);//尾插法
    //pktblock_alloc_list(size, 1);//头插法
    pktbuf_t *buf = mblock_alloc(&pktbuf_list, -1);
    if (!buf) {
        dbg_error(DBG_BUF, "no buffer");
        return (pktbuf_t *)0;
    }

    buf->total_size = 0;
    nlist_init(&buf->blk_list);
    nlist_node_init(&buf->node);

    if (size) {
        pktblk_t *block = pktblock_alloc_list(size, 1);
        if (!block) {
            mblock_free(&pktbuf_list, buf);
            return (pktbuf_t *)0;
        }

        pktbuf_insert_blk_list(buf, block, 1);
    }

    display_check_buf(buf);

    return buf;
}
void pktbuf_free (pktbuf_t *buf) {
    pktblock_free_list(pktbuf_first_blk(buf));
    mblock_free(&pktbuf_list, buf);
}

net_err_t pktbuf_add_header(pktbuf_t *buf, int size, int cont) {
    pktblk_t *block = pktbuf_first_blk(buf);

    //前面有多余的存储空间可以存储包头
    int resv_size = (int)(block->data - block->payload);
    if (size <= resv_size) {
        block->size += size;
        block->data -= size;
        buf->total_size += size;

        display_check_buf(buf);
        return NET_ERR_OK;
    }

    if (cont) {
        if (size > PKTBUF_BLK_SIZE) {
            dbg_error(DBG_BUF, "set cont, size too big: %d > %d\n", size, PKTBUF_BLK_SIZE);
            return NET_ERR_SIZE;
        }

        block = pktblock_alloc_list(size, 1);//使用头插法
        if (!block) {
            dbg_error(DBG_BUF, "no buffer (size %d)", size);
            return NET_ERR_NONE;
        }
    } else {
        //包头不连续的情况,将剩下的一小部分利用,再分配一个新的存剩余的包头
        block->data = block->payload;
        block->size += resv_size;
        buf->total_size += resv_size;
        size -= resv_size;

        block = pktblock_alloc_list(size, 1);//根据size大小分配需要的块数
        if (!block) {
            dbg_error(DBG_BUF, "no buffer (size %d)", size);
            return NET_ERR_NONE;
        }
    }

    pktbuf_insert_blk_list(buf, block, 0);//头部插入
    display_check_buf(buf);
    return NET_ERR_OK;
}

net_err_t pktbuf_remove_header(pktbuf_t *buf, int size) {
    pktblk_t *block = pktbuf_first_blk(buf);

    while (size) {
        pktblk_t* next_blk = pktblk_blk_next(block);//获取下个数据包
        //当空间大于要移除的包头大小时,此时除了包头,还有其他数据,直接指针偏移即可
        if (size < block->size) {
            block->data += size;
            block->size -= size;
            buf->total_size -= size;
            break;
        }
        //当要移除的包头的大小大于当前包的大小时,
        //说明此时该包除了包头数据,没有载荷了,故直接移除
        int curr_size = block->size;
        nlist_remove_first(&buf->blk_list);
        pktblock_free(block);
        
        size -= curr_size;
        buf->total_size -= curr_size;

        block = next_blk;
    }

    display_check_buf(buf);
    return NET_ERR_OK;
}