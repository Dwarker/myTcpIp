#include "tcp_buf.h"
#include "net_cfg.h"

void tcp_buf_init(tcp_buf_t *buf, uint8_t *data, int size) {
    buf->in = buf->out = 0;
    buf->count = 0;
    buf->size = size;
    buf->data = data;
}

void tcp_buf_write_send(tcp_buf_t *buf, const uint8_t *buffer, int len) {
    while (len > 0) {
        buf->data[buf->in++] = *buffer++;
        if (buf->in >= buf->size) {
            buf->in = 0;
        }
        len--;
        buf->count++;
    }
}

void tcp_buf_read_send(tcp_buf_t * buf, int offset, pktbuf_t * dest, int count) {
    // 超过要求的数据量，进行调整
    int free_for_us = buf->count - offset;  //跳过offset之前的数据,offset是已发送但未确认的大小
    if (count > free_for_us) {
        //dbg_warning(DBG_TCP, "resize for send: %d -> %d", count, free_for_us);
        count = free_for_us;
    }
    
    // 复制过程中要考虑buf中的数据回绕的问题
    int start = buf->out + offset;     // 注意拷贝的偏移
    if (start >= buf->size) {
        start -= buf->size;
    }

    while (count > 0) {
        // 当前超过末端，则只拷贝到末端的区域
        int end = start + count;
        if (end >= buf->size) {
            end = buf->size;
        }
        int copy_size = (int)(end - start);

        // 写入数据
        net_err_t err = pktbuf_write(dest, buf->data + start, (int)copy_size);
        //dbg_assert(err >= 0, "write buffer failed.");

        // 更新start，处理回绕的问题
        start += copy_size;
        if (start >= buf->size) {
            start -= buf->size;
        }
        count -= copy_size;

        // 不调整buf中的count和out，因为只当被确认时才需要
    }
}

/**
 * @brief 写接收缓存。当从网络上接收数据时，从src中提出数据写入dest中
 */
//需要再看
int tcp_buf_write_rcv(tcp_buf_t * dest, int offset, pktbuf_t * src, int total) {
    // 计算缓冲区中的起始索引，注意回绕
    int start = dest->in + offset;
    if (start >= dest->size) {
        start = start - dest->size;
    }

    // 计算实际可写的数据量
    int free_size = tcp_buf_free_cnt(dest) - offset;            // 跳过的一部分相当于是已经被写入了
    total = (total > free_size) ? free_size : total;

    int size = total;
    while (size > 0) {
        // 从start到缓存末端的单元数量，可能其中有数据也可能没有
        int free_to_end = dest->size - start;

        // 大小超过到尾部的空闲数据量，只拷贝一部分
        int curr_copy = size > free_to_end ? free_to_end : size;
        pktbuf_read(src, dest->data + start, (int)curr_copy);

        // 增加写索引，注意回绕
        start += curr_copy;
        if (start >= dest->size) {
            start = start - dest->size;
        }

        // 增加已写入的数据量
        dest->count += curr_copy;
        size -= curr_copy;
    }

    dest->in = start;
    return total;
}

//cnt:想要删除的数据量
int tcp_buf_remove(tcp_buf_t *buf, int cnt) {
    if (cnt > buf->count) {
        cnt = buf->count;
    }

    buf->out += cnt;
    if (buf->out >= buf->size) {
        buf->out -= buf->size;
    }

    buf->count -= cnt;
    return cnt;
}