#include "tcp_out.h"
#include "pktbuf.h"
#include "dbg.h"
#include "tools.h"
#include "protocol.h"
#include "ipv4.h"
#include "tcp.h"

static net_err_t send_out(tcp_hdr_t *out, pktbuf_t *buf, ipaddr_t *dest, ipaddr_t *src) {
    tcp_show_pkt("tcp out", out, buf);

    out->sport = x_htons(out->sport);
    out->dport = x_htons(out->dport);
    out->seq = x_htonl(out->seq);
    out->ack = x_htonl(out->ack);
    out->win = x_htons(out->win);
    out->urgptr = x_htons(out->urgptr);

    out->checksum = 0;
    out->checksum = checksum_peso(buf, dest, src, NET_PROTOCOL_TCP);

    net_err_t err = ipv4_out(NET_PROTOCOL_TCP, dest, src, buf);
    if (err < 0) {
        dbg_warning(DBG_TCP, "send tcp error");
        pktbuf_free(buf);
        return err;
    }

    return NET_ERR_OK;
}

net_err_t tcp_send_reset(tcp_seg_t *seg) {
    tcp_hdr_t *in = seg->hdr;

    pktbuf_t *buf = pktbuf_alloc(sizeof(tcp_hdr_t));
    if (!buf) {
        dbg_warning(DBG_TCP, "no pktbuf");
        return NET_ERR_NONE;
    }

    tcp_hdr_t *out = (tcp_hdr_t *)pktbuf_data(buf);
    out->sport = in->dport;
    out->dport = in->sport;
    out->flag = 0;
    out->f_rst = 1;
    tcp_set_hdr_size(out, sizeof(tcp_hdr_t));//设置头部大小字段
    //暂时设置为0
    out->win = out->urgptr = 0;

    //数据发送过程中,突然出问题,发reset
    if (in->f_ack) {
        //这是对方希望的ack值,告诉对方我收到了
        out->seq = in->ack;

        //因为seq已经可以告诉对方我收到了,所以不需要设置ack
        out->ack = 0;
        out->f_ack = 0;
    } else {
        //三次握手,第一次握手被拒的情况
        //因为对方没有ack值,所以我们不知道对方期待的seq值是多少,
        //也就无法填seq值发给对方,所以我们只需填ack,告诉对方,
        //你的syn包我收到了,但是seq的值我们直接填0
        out->seq = 0;
        out->ack = in->seq + seg->seq_len;//告诉对方你的syn包我收到了
        out->f_ack = 1;
    }

    return send_out(out, buf, &seg->remote_ip, &seg->local_ip);
}

static int copy_send_data(tcp_t *tcp, pktbuf_t *buf, int doff, int dlen) {
    if (dlen == 0) {
        return 0;
    }

    net_err_t err = pktbuf_resize(buf, (int)buf->total_size + dlen);
    if (err < 0) {
        dbg_error(DBG_TCP, "pktbuf resize error.");
        return -1;
    }

    int hdr_size = tcp_hdr_size((tcp_hdr_t *)pktbuf_data(buf));
    pktbuf_reset_acc(buf);
    pktbuf_seek(buf, hdr_size);//定位到数据区

    //拷贝至buf
    tcp_buf_read_send(&tcp->snd.buf, doff, buf, dlen);

    return dlen;
}

/*
syn--------X-------Y-----Z----FIN
------------------una----nxt----
-------------------20------25
x:已确认发送
Y:已发送未确认 即una,下标为20
Z:待发送 即nxt 下标为25
所以nxt-una 的意思是当前已发送但是未收到确认的大小
用buf->count-(nxt-una) 即剩余数据大小(包含未确认的部分)-未确认的部分
结果就是dlen,也就是待发送的大小
*/
static void get_send_info(tcp_t *tcp, int *doff, int *dlen) {
    *doff = tcp->snd.nxt - tcp->snd.una;
    *dlen = tcp_buf_cnt(&tcp->snd.buf) - *doff;

    *dlen = (*dlen > tcp->mss) ? tcp->mss : *dlen;
}

net_err_t tcp_transmit(tcp_t *tcp) {
    pktbuf_t *buf = pktbuf_alloc(sizeof(tcp_hdr_t));
    if (!buf) {
        dbg_error(DBG_TCP, "no buffer.");
        return NET_ERR_OK;
    }

    tcp_hdr_t *hdr = (tcp_hdr_t *)pktbuf_data(buf);
    plat_memset(hdr, 0, sizeof(tcp_hdr_t));

    hdr->sport = tcp->base.local_port;
    hdr->dport = tcp->base.remote_port;
    hdr->seq = tcp->snd.nxt; //nxt值已初始化为0
    hdr->ack = tcp->rcv.nxt; //告诉对方,我方希望接收的序列号是0(也就是还没收到数据)
    hdr->flag = 0;
    hdr->f_syn = tcp->flags.syn_out;
    //是否已经收到对方的报文(如三次握手发送syn的时候,这里为0,
    //此时hdr->ack这个值也是无效的,是0
    //收到对方syn+ack后,tcp->flags.irs_valid被置为1,那么这里的f_ack的值也就为1
    hdr->f_ack = tcp->flags.irs_valid;
    hdr->f_fin = tcp->flags.fin_out; //tcp_send_fin中设置,表示这是个fin包
    hdr->win = 1024; //暂时填这个
    hdr->urgptr = 0; //用不到
    tcp_set_hdr_size(hdr, sizeof(tcp_hdr_t));

    int dlen, doff;//dlen:应该发送多少数据, doff:从发送缓存区的哪个位置去取(如果从0位置开始拷贝,那么这个值相当于已发送的大小)
    get_send_info(tcp, &doff, &dlen);
    //如果是三次握手期间,发送syn或者fin的时候,dlen的值为0,
    //此时不归属于错误,所以下面这个if判断里面,dlen==0的判断要去掉
    if (dlen < 0) {
        return NET_ERR_OK;
    }

    //将tcp发送缓存里面的数据拷贝到buf中,buf会被传入驱动层进行数据发送
    //doff:从发送缓存区的哪个位置开始拷贝,dlen:需要拷贝多少数据
    copy_send_data(tcp, buf, doff, dlen);

    tcp->snd.nxt += hdr->f_syn + hdr->f_fin + dlen;//调整待发送的序号

    return send_out(hdr, buf, &tcp->base.remote_ip, &tcp->base.local_ip);
}

net_err_t tcp_send_syn(tcp_t *tcp) {
    tcp->flags.syn_out = 1;
    tcp_transmit(tcp);

    return NET_ERR_OK;
}

//争对我们发给对方的数据,对方的处理结果,这里是对这个处理结果进行处理
net_err_t tcp_ack_process(tcp_t *tcp, tcp_seg_t *seg) {
    tcp_hdr_t *tcp_hdr = seg->hdr;
    
    //服务端发送fin的时候syn_out这个值是0,因为前面的数据都已经被接收了
    if (tcp->flags.syn_out) {
        //下一个待确认的序列号,因为是争对第一次握手syn的回包处理,
        //所以下一个已发送,待确认的数据包就是第一个字节的序列号,加1即可
        tcp->snd.una++;
        tcp->flags.syn_out = 0;//清零,表示该包不需要做重传了
    }

    //获取到此次确认的大小
    int acked_cnt = tcp_hdr->ack - tcp->snd.una;
    //未确认的总大小
    int unacked = tcp->snd.nxt - tcp->snd.una;
    //acked_cnt比unacked大的话,应该是有问题的?
    int curr_acked = (acked_cnt > unacked) ? unacked : acked_cnt;
    if (curr_acked > 0) {
        tcp->snd.una += curr_acked;

        //移除此次已确认对方收到的数据
        //因为curr_acked这个可能包含了FIN,
        curr_acked -= tcp_buf_remove(&tcp->snd.buf, curr_acked);
        //如果包含了FIN,则上一句代码,curr_acked的最终结果是1

        //用于两边同时关闭的处理,还没搞明白?
        if (tcp->flags.fin_out && curr_acked) {
            tcp->flags.fin_out = 0;
        }

        //如果应用侧有正在写等待的,此时唤醒
        sock_wakeup(&tcp->base, SOCK_WAIT_WRITE, NET_ERR_OK);
    }

    return NET_ERR_OK;
}

//这里不用tcp_transmit接口进行发送,
//是因为第三次握手回复功能单一独立,
//而tcp_transmit较复杂
net_err_t tcp_send_ack(tcp_t *tcp, tcp_seg_t *seg) {
    pktbuf_t *buf = pktbuf_alloc(sizeof(tcp_hdr_t));
    if (!buf) {
        dbg_error(DBG_TCP, "no buffer.");
        return NET_ERR_NONE;
    }

    tcp_hdr_t *hdr = (tcp_hdr_t *)pktbuf_data(buf);
    plat_memset(hdr, 0, sizeof(tcp_hdr_t));

    hdr->sport = tcp->base.local_port;
    hdr->dport = tcp->base.remote_port;
    hdr->seq = tcp->snd.nxt; //nxt值已初始化为0
    hdr->ack = tcp->rcv.nxt; //告诉对方,我方希望接收的序列号是0(也就是还没收到数据)
    hdr->flag = 0;
    hdr->f_ack = 1;//表示我收到你们的包了
    hdr->win = 1024; //暂时填这个
    hdr->urgptr = 0; //用不到
    tcp_set_hdr_size(hdr, sizeof(tcp_hdr_t));

    return send_out(hdr, buf, &tcp->base.remote_ip, &tcp->base.local_ip);
}

net_err_t tcp_send_fin(tcp_t *tcp) {
    tcp->flags.fin_out = 1;
    tcp_transmit(tcp);
    return NET_ERR_OK;
}

int tcp_write_sndbuf(tcp_t *tcp, const uint8_t *buf, int len) {
    int free_cnt = tcp_buf_free_cnt(&tcp->snd.buf);
    if (free_cnt < 0) {
        return 0;
    }

    int wr_len = (len > free_cnt) ? free_cnt : len;
    tcp_buf_write_send(&tcp->snd.buf, buf, wr_len);
    return wr_len;
}