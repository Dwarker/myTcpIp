#include "pktbuf.h"
#include "dbg.h"
#include "mblock.h"
#include "nlocker.h"
#include "sys.h"

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

static inline int total_blk_remain (pktbuf_t *buf) {
    return buf->total_size - buf->pos;
}

static int curr_blk_remain (pktbuf_t *buf) {
    pktblk_t *block = buf->curr_blk;
    if (!block) {
        return 0;
    }
    //该块未使用空间大小
    return (int)(buf->curr_blk->data + block->size - buf->blk_offset);
}

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
    mblock_init(&block_list, block_buffer, sizeof(pktblk_t), PKTBUF_BLK_CNT, NLOCKER_NONE);
    mblock_init(&pktbuf_list, pktbuf_buffer, sizeof(pktbuf_t), PKTBUF_BUF_CNT, NLOCKER_NONE);
    
    dbg_info(DBG_BUF, "init done");
    return NET_ERR_OK;
}

static pktblk_t *pktblock_alloc (void) {
    //arm中可能会被中断调用,所以不能用阻塞,这里传-1
    nlocker_lock(&locker);
    pktblk_t *block = mblock_alloc(&block_list, -1);
    nlocker_unlock(&locker);
    if (block) {
        block->size = 0;
        block->data = (uint8_t *)0;
        nlist_node_init(&block->node);
    }
    return block;
}

static void pktblock_free (pktblk_t *block) {
    nlocker_lock(&locker);
    mblock_free(&block_list, block);
    nlocker_unlock(&locker);
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
            if (first_block) {
                pktblock_free_list(first_block);
            }
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

void pktbuf_inc_ref (pktbuf_t *buf) {
    nlocker_lock(&locker);
    buf->ref++;
    nlocker_unlock(&locker);
}

pktbuf_t *pktbuf_alloc (int size) {
    //pktblock_alloc_list(size, 0);//尾插法
    //pktblock_alloc_list(size, 1);//头插法
    nlocker_lock(&locker);
    pktbuf_t *buf = mblock_alloc(&pktbuf_list, -1);
    nlocker_unlock(&locker);
    if (!buf) {
        dbg_error(DBG_BUF, "no buffer");
        return (pktbuf_t *)0;
    }

    buf->total_size = 0;
    buf->ref = 1;   //分配出去了,引用加1
    nlist_init(&buf->blk_list);
    nlist_node_init(&buf->node);

    if (size) {
        pktblk_t *block = pktblock_alloc_list(size, 1);
        if (!block) {
            nlocker_lock(&locker);
            mblock_free(&pktbuf_list, buf);
            nlocker_unlock(&locker);
            return (pktbuf_t *)0;
        }

        pktbuf_insert_blk_list(buf, block, 1);
    }
    //可能分配后立即读写,所以分配后立马重置
    pktbuf_reset_acc(buf);

    display_check_buf(buf);

    return buf;
}
void pktbuf_free (pktbuf_t *buf) {
    nlocker_lock(&locker);
    if (--buf->ref == 0) {
        pktblock_free_list(pktbuf_first_blk(buf));
        mblock_free(&pktbuf_list, buf);
    }
    nlocker_unlock(&locker);
}

net_err_t pktbuf_add_header(pktbuf_t *buf, int size, int cont) {
    dbg_assert(buf->ref != 0, "buf ref == 0");

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
    dbg_assert(buf->ref != 0, "buf ref == 0");

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

net_err_t pktbuf_resize(pktbuf_t *buf, int to_size) {
    dbg_assert(buf->ref != 0, "buf ref == 0");

    if (to_size == buf->total_size) {
        return NET_ERR_OK;
    }

    if (buf->total_size == 0) {
        pktblk_t *blk = pktblock_alloc_list(to_size, 0);//尾插法
        if (!blk) {
            dbg_error(DBG_BUF, "no block");
            return NET_ERR_MEM;
        }

        pktbuf_insert_blk_list(buf, blk, 1);//尾插法
    } else if (to_size == 0) {
        pktblock_free_list(pktbuf_first_blk(buf));
        buf->total_size = 0;
        nlist_init(&buf->blk_list);
    } else if (to_size > buf->total_size) {
        //分为两种情况,一种是当前包的剩余空间满足,另外一种则是需要新增一个甚至多个包
        pktblk_t *tail_blk = pktbuf_last_blk(buf);

        int inc_size = to_size - buf->total_size;
        int remain_size = curr_blk_tail_free(tail_blk);
        if (remain_size >= inc_size) {
            tail_blk->size += inc_size;
            buf->total_size += inc_size;
        } else {
            pktblk_t *new_blks = pktblock_alloc_list(inc_size - remain_size, 0);//尾插法
            if (!new_blks) {
                dbg_error(DBG_BUF, "no block");
                return NET_ERR_MEM;
            }

            tail_blk->size += remain_size;//当前已有的空间利用上
            buf->total_size += remain_size;

            pktbuf_insert_blk_list(buf, new_blks, 1);//尾插法插入
        }
    } else {
        //缩小数据包
        int total_size = 0;
        pktblk_t *tail_blk;
        for (tail_blk = pktbuf_first_blk(buf); tail_blk; tail_blk = pktblk_blk_next(tail_blk)) {
            total_size += tail_blk->size;
            if (total_size >= to_size) {
                break;
            }
        }

        if (tail_blk == (pktblk_t *)0) {
            return NET_ERR_SIZE;
        }

        total_size = 0;
        pktblk_t *curr_blk = pktblk_blk_next(tail_blk);
        while (curr_blk) {
            pktblk_t *next_blk = pktblk_blk_next(curr_blk);

            total_size += curr_blk->size;
            nlist_remove(&buf->blk_list, &curr_blk->node);
            pktblock_free(curr_blk);
            curr_blk = next_blk;
        }
        //最后一个数据包占有小部分数据,而这部分数据需要移除,调整大小即可
        //总数据包的大小 - 已经移除的大小,结果其实还包含了一个数据包中的一小部分,
        //这个结果减去需要保留的大小,就是剩下的要移除的一小部分大小(..有点绕)
        tail_blk->size -= (buf->total_size - total_size - to_size);

        buf->total_size = to_size;
    }

    display_check_buf(buf);
    return NET_ERR_OK;
}

net_err_t pktbuf_join(pktbuf_t *dest, pktbuf_t *src) {
    dbg_assert(dest->ref != 0, "dest ref == 0");
    dbg_assert(src->ref != 0, "src ref == 0");

    pktblk_t *first;

    while ((first = pktbuf_first_blk(src))) {
        nlist_remove_first(&src->blk_list);
        pktbuf_insert_blk_list(dest, first, 1);//数据包大小在这个调用里面调整了
    }

    pktbuf_free(src);
    display_check_buf(dest);
    return NET_ERR_OK;
}

net_err_t pktbuf_set_cont(pktbuf_t *buf, int size) {
    dbg_assert(buf->ref != 0, "buf ref == 0");

    //合并的大小超过了整个数据包链表的总大小
    if (size > buf->total_size) {
        dbg_error(DBG_BUF, "size %d > total_size %d\n", size, buf->total_size);
        return NET_ERR_SIZE;
    }

    //要合并的大小超过一个数据包的大小
    if (size > PKTBUF_BLK_SIZE) {
        dbg_error(DBG_BUF, "size too big: %d > %d", size, PKTBUF_BLK_SIZE);
        return NET_ERR_SIZE;
    }
    
    //不需要合并的情况
    pktblk_t *first_blk = pktbuf_first_blk(buf);
    if (size <= first_blk->size) {
        display_check_buf(buf);
        return NET_ERR_OK;
    }
    uint8_t *dest = first_blk->payload;
    for (int i = 0; i < first_blk->size; i++) {
        *dest++ = first_blk->data[i];
    }
    first_blk->data = first_blk->payload;
    
    pktblk_t *curr_blk = pktblk_blk_next(first_blk);
    int remain_size = size - first_blk->size;//剩下要合并的大小
    while (remain_size && curr_blk) {
        int curr_size = (curr_blk->size > remain_size) ? remain_size : curr_blk->size;

        plat_memcpy(dest, curr_blk->data, curr_size);
        dest += curr_size;
        curr_blk->data += curr_size;//该块的包头已被合并,故调整数据起始位置
        curr_blk->size -= curr_size;
        first_blk->size += curr_size;
        remain_size -= curr_size;

        //搬运后判断该包是否还有数据,没有则删除
        if (curr_blk->size == 0) {
            pktblk_t *next_blk = pktblk_blk_next(curr_blk);
            nlist_remove(&buf->blk_list, &curr_blk->node);
            pktblock_free(curr_blk);
            curr_blk = next_blk;
        }
    }
    display_check_buf(buf);
    return NET_ERR_OK;
}

void pktbuf_reset_acc(pktbuf_t *buf) {
    dbg_assert(buf->ref != 0, "buf ref == 0");

    if (buf) {
        buf->pos = 0;
        buf->curr_blk = pktbuf_first_blk(buf);
        buf->blk_offset = buf->curr_blk ? buf->curr_blk->data : (uint8_t *)0;
    }
}

static void move_forward (pktbuf_t *buf, int size) {
    dbg_assert(buf->ref != 0, "buf ref == 0");

    buf->pos += size;
    buf->blk_offset += size;

    pktblk_t* curr = buf->curr_blk;
    if (buf->blk_offset >= curr->data + curr->size) {
        buf->curr_blk = pktblk_blk_next(curr);
        if (buf->curr_blk) {
            buf->blk_offset = buf->curr_blk->data;
        } else {
            buf->blk_offset = (uint8_t *)0;
        }
    }
}

net_err_t pktbuf_write (pktbuf_t *buf, uint8_t *src, int size) {
    dbg_assert(buf->ref != 0, "buf ref == 0");

    if (!src || !size) {
        return NET_ERR_PARAM;
    }

    //计算当前数据包链表中剩余可用空间是否满足
    int remain_size = total_blk_remain(buf);
    if (remain_size < size) {
        dbg_error(DBG_BUF, "size error: %d < %d", remain_size, size);
        return NET_ERR_SIZE;
    }

    while (size) {
        int blk_size = curr_blk_remain(buf);

        int curr_copy = size > blk_size ? blk_size : size;
        plat_memcpy(buf->blk_offset, src, curr_copy);
        src += curr_copy;
        size -= curr_copy;

        move_forward(buf, curr_copy);//移动指标
    }

    return NET_ERR_OK;
}

net_err_t pktbuf_read (pktbuf_t *buf, uint8_t *dest, int size) {
    dbg_assert(buf->ref != 0, "buf ref == 0");

    if (!dest || !size) {
        return NET_ERR_PARAM;
    }

    //计算当前数据包链表中剩余可用空间是否满足
    int remain_size = total_blk_remain(buf);
    if (remain_size < size) {
        dbg_error(DBG_BUF, "size error: %d < %d", remain_size, size);
        return NET_ERR_SIZE;
    }

    while (size) {
        int blk_size = curr_blk_remain(buf);

        int curr_copy = size > blk_size ? blk_size : size;
        plat_memcpy(dest, buf->blk_offset, curr_copy);

        dest += curr_copy;
        size -= curr_copy;

        move_forward(buf, curr_copy);//移动指标
    }

    return NET_ERR_OK;
}

net_err_t pktbuf_seek (pktbuf_t *buf, int offset) {
    dbg_assert(buf->ref != 0, "buf ref == 0");

    if (buf->pos == offset) {
        return NET_ERR_OK;
    }

    if ((offset < 0) || (offset >= buf->total_size)) {
        return NET_ERR_SIZE;
    }

    int move_bytes;
    //往前移:定位到第一个块,然后再根据offset定位到相应的位置
    if (offset < buf->pos) {
        buf->curr_blk = pktbuf_first_blk(buf);
        buf->blk_offset = buf->curr_blk->data;
        buf->pos = 0;
        move_bytes = offset;
    } else {
        //往后移
        move_bytes = offset - buf->pos;
    }

    while (move_bytes) {
        int remain_size = curr_blk_remain(buf);
        int curr_move = move_bytes > remain_size ? remain_size : move_bytes;

        move_forward(buf, curr_move);
        move_bytes -= curr_move;
    }

    return NET_ERR_OK;
}

net_err_t pktbuf_copy (pktbuf_t *dest, pktbuf_t *src, int size) {
    dbg_assert(dest->ref != 0, "dest ref == 0");
    dbg_assert(src->ref != 0, "src ref == 0");

    if ((total_blk_remain(dest) < size) 
        || total_blk_remain(src) < size) {
        return NET_ERR_SIZE;
    }

    while (size) {
        int dest_remain = curr_blk_remain(dest);
        int src_remain = curr_blk_remain(src);
        int copy_size = dest_remain > src_remain ? src_remain : dest_remain;
    
        copy_size = copy_size > size ? size : copy_size;
        plat_memcpy(dest->blk_offset, src->blk_offset, copy_size);

        //前移后,继续往后做拷贝
        move_forward(dest, copy_size);
        move_forward(src, copy_size);
        size -= copy_size;
    }

    return NET_ERR_OK;
}

net_err_t pktbuf_fill (pktbuf_t *buf, uint8_t value, int size) {
    dbg_assert(buf->ref != 0, "buf ref == 0");

    if (!size) {
        return NET_ERR_PARAM;
    }

    //计算当前数据包链表中剩余可用空间是否满足
    int remain_size = total_blk_remain(buf);
    if (remain_size < size) {
        dbg_error(DBG_BUF, "size error: %d < %d", remain_size, size);
        return NET_ERR_SIZE;
    }

    while (size) {
        int blk_size = curr_blk_remain(buf);

        int curr_fill = size > blk_size ? blk_size : size;
        plat_memset(buf->blk_offset, value, curr_fill);

        size -= curr_fill;

        move_forward(buf, curr_fill);//移动指标
    }

    return NET_ERR_OK;
}