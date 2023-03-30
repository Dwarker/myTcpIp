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

    tcp->snd.nxt += hdr->f_syn + hdr->f_fin;//调整待发送的序号

    return send_out(hdr, buf, &tcp->base.remote_ip, &tcp->base.local_ip);
}

net_err_t tcp_send_syn(tcp_t *tcp) {
    tcp->flags.syn_out = 1;
    tcp_transmit(tcp);

    return NET_ERR_OK;
}

net_err_t tcp_ack_process(tcp_t *tcp, tcp_seg_t *seg) {
    tcp_hdr_t *tcp_hdr = seg->hdr;
    
    //服务端发送fin的时候syn_out这个值是0,因为前面的数据都已经被接收了
    if (tcp->flags.syn_out) {
        //下一个待确认的序列号,因为是争对第一次握手syn的回包处理,
        //所以下一个已发送,待确认的数据包就是第一个字节的序列号,加1即可
        tcp->snd.una++;
        tcp->flags.syn_out = 0;//清零,表示该包不需要做重传了
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