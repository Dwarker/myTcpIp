#include "tcp_in.h"
#include "pktbuf.h"
#include "ipaddr.h"
#include "tools.h"
#include "dbg.h"
#include "protocol.h"
#include "tcp_out.h"
#include "tcp_state.h"

//后面对数据包处理的时候,是对seg进行处理,这样比较方便
void tcp_seg_init(tcp_seg_t *seg, pktbuf_t *buf, ipaddr_t *local, ipaddr_t *remote) {
    seg->buf = buf;
    seg->hdr = (tcp_hdr_t *)pktbuf_data(buf);

    ipaddr_copy(&seg->local_ip, local);
    ipaddr_copy(&seg->remote_ip, remote);
    seg->data_len = buf->total_size - tcp_hdr_size(seg->hdr);
    seg->seq = seg->hdr->seq;
    seg->seq_len = seg->data_len + seg->hdr->f_syn + seg->hdr->f_fin;
}

net_err_t tcp_in(pktbuf_t *buf, ipaddr_t *src_ip, ipaddr_t *dest_ip) {
    static const tcp_proc_t tcp_state_proc[] = {
        [TCP_STATE_CLOSED] = tcp_closed_in,
        [TCP_STATE_LISTEN] = tcp_listen_in,
        [TCP_STATE_SYN_SENT] = tcp_syn_sent_in,
        [TCP_STATE_SYN_RECVD] = tcp_syn_recvd_in,
        [TCP_STATE_ESTABLISHED] = tcp_established_in,
        [TCP_STATE_FIN_WAIT_1] = tcp_fin_wait_1_in,
        [TCP_STATE_FIN_WAIT_2] = tcp_fin_wait_2_in,
        [TCP_STATE_CLOSING] = tcp_closing_in,
        [TCP_STATE_TIME_WAIT] = tcp_time_wait_in,
        [TCP_STATE_CLOSE_WAIT] = tcp_close_wait_in,
        [TCP_STATE_LAST_ACK] = tcp_last_ack_in,
    };

    tcp_hdr_t *tcp_hdr = (tcp_hdr_t *)pktbuf_data(buf);
    if (tcp_hdr->checksum) {
        pktbuf_reset_acc(buf);
        if (checksum_peso(buf, dest_ip, src_ip, NET_PROTOCOL_TCP)) {
            dbg_warning(DBG_TCP, "tcp check sum failed.");
            return NET_ERR_BROKEN;
        }
    }

    if ((buf->total_size < sizeof(tcp_hdr_t)) 
        || (buf->total_size < tcp_hdr_size(tcp_hdr))) {
        dbg_warning(DBG_TCP, "tcp pkt size error.");
        return NET_ERR_SIZE;
    }

    if (!tcp_hdr->sport || !tcp_hdr->dport) {
        dbg_warning(DBG_TCP, "port == 0");
        return NET_ERR_BROKEN;
    }

    if (tcp_hdr->flag == 0) {
        dbg_warning(DBG_TCP, "flag == 0");
        return NET_ERR_BROKEN;
    }

    tcp_hdr->sport = x_ntohs(tcp_hdr->sport);
    tcp_hdr->dport = x_ntohs(tcp_hdr->dport);
    tcp_hdr->seq = x_ntohl(tcp_hdr->seq);
    tcp_hdr->ack = x_ntohl(tcp_hdr->ack);
    tcp_hdr->win = x_ntohs(tcp_hdr->win);
    tcp_hdr->urgptr = x_ntohs(tcp_hdr->urgptr);

    tcp_show_pkt("tcp in", tcp_hdr, buf);

    tcp_seg_t seg;
    tcp_seg_init(&seg, buf, dest_ip, src_ip);

    tcp_t *tcp = tcp_find(dest_ip, tcp_hdr->dport, src_ip, tcp_hdr->sport);
    if (!tcp) {
        dbg_info(DBG_TCP, "no tcp found");
        //tcp_send_reset(&seg);
        tcp_closed_in((tcp_t *)0, &seg);
        pktbuf_free(buf);

        tcp_show_list();
        return NET_ERR_OK;
    }

    //上面并未移除tcp包头,而后面是对应用层的数据进行操作,
    //所以这里将数据位置偏移一下
    net_err_t err = pktbuf_seek(buf, tcp_hdr_size(tcp_hdr));
    if (err < 0) {
        dbg_error(DBG_TCP, "seek failed.");
        return NET_ERR_SIZE;
    }

    tcp_state_proc[tcp->state](tcp, &seg);
    tcp_show_info("after tcp in", tcp);

    //tcp_show_list();

    pktbuf_free(buf);//这里如是应用层还没读取,这里就释放?
    return NET_ERR_OK;
}


static int copy_data_to_rcvbuf(tcp_t *tcp, tcp_seg_t *seg) {
    int doffset = seg->seq - tcp->rcv.nxt;//正常情况下,希望对方发的序列号和对方发的序列号是相等的
    if (seg->data_len && (doffset == 0)) {
        //doffset是缓冲区中应该放的位置,而不是第一个空的位置,
        //因为有可能发生重传,比如已有ab,然后服务端以为ab丢了,就重传了abcd
        //所以会根据rcv.nxt和发生过来包的seq值去判断
        return tcp_buf_write_rcv(&tcp->rcv.buf, doffset, seg->buf, seg->data_len);
    }

    return 0;
}

//目前只做对方发送过来的fin的处理
net_err_t tcp_data_in(tcp_t *tcp, tcp_seg_t *seg) {
    //tcp_buf_write_rcv(&tcp->rcv.buf, 0, seg->buf, seg->data_len);
    int size = copy_data_to_rcvbuf(tcp, seg);
    if (size < 0) {
        dbg_error(DBG_TCP, "copy data to rcvbuf failed.");
        return NET_ERR_SIZE;
    }

    int wakeup = 0;

    //调整nxt的值
    if (size) {
        tcp->rcv.nxt += size;
        //此时缓冲区有数据了,而上层应用可能正在等待数据,
        //这样,下面就会唤醒上层应用程序
        wakeup++;
    }

    tcp_hdr_t *tcp_hdr = seg->hdr;
    if (tcp_hdr->f_fin) {
        //将期望对方下次再发送的序列号进行加1,
        //因为是fin包,所以不携带数据,只加1即可
        tcp->rcv.nxt++;//这里因为自增了,所以发送的时候(tcp_send_ack),ack会被赋值tcp->rcv.nxt

        wakeup++;
    }

    //如果此时上层应用正在recv/read的时候收到fin,则通知上层应用终止数据传输
    
    if (wakeup) {
        if (tcp_hdr->f_fin) {
            sock_wakeup(&tcp->base, SOCK_WAIT_ALL, NET_ERR_CLOSE);
        } else {
            //这里目前应该走不到吧?
            sock_wakeup(&tcp->base, SOCK_WAIT_READ, NET_ERR_OK);
        }

        tcp_send_ack(tcp, seg);
    }

    return NET_ERR_OK;
}