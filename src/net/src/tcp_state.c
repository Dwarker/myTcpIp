#include "tcp_state.h"
#include "tcp_out.h"

const char *tcp_state_name(tcp_state_t state) {
    static const char* state_name[] = {
        [TCP_STATE_CLOSED] = "CLOSED",
        [TCP_STATE_LISTEN] = "LISTEN",
        [TCP_STATE_SYN_SENT] = "SYN_SENT",
        [TCP_STATE_SYN_RECVD] = "SYN_RECVD",
        [TCP_STATE_ESTABLISHED] = "ESTABLISHED",
        [TCP_STATE_FIN_WAIT_1] = "FIN_WAIT_1",
        [TCP_STATE_FIN_WAIT_2] = "FIN_WAIT_2",
        [TCP_STATE_CLOSING] = "CLOSING",
        [TCP_STATE_TIME_WAIT] = "TIME_WAIT",
        [TCP_STATE_CLOSE_WAIT] = "CLOSE_WAIT",
        [TCP_STATE_LAST_ACK] = "LAST_ACK",
        [TCP_STATE_MAX] = "UNKNOW",
    };

    if (state > TCP_STATE_MAX) {
        state = TCP_STATE_MAX;
    }

    return state_name[state];
}

void tcp_set_state(tcp_t *tcp, tcp_state_t state) {
    tcp->state = state;
    tcp_show_info("tcp set state", tcp);
}

net_err_t tcp_closed_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_listen_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_syn_sent_in(tcp_t *tcp, tcp_seg_t *seg) {
    //收到对方对syn的回复
    tcp_hdr_t *tcp_hdr = seg->hdr;

    if (tcp_hdr->f_ack) {
        //检查返回的ack值是否在合理范围,也就是数据待确认范围
        if ((tcp_hdr->ack - tcp->snd.iss <= 0
            || (tcp_hdr->ack - tcp->snd.nxt > 0))) {
            dbg_warning(DBG_TCP, "%s: ack error", tcp_state_name(tcp->state));
            return tcp_send_reset(seg);
        }
    }

    //可能是争对syn的复位应答
    if (tcp_hdr->f_rst) {
        //这里如果f_ack是0,说明没有通过上一个if的检查,
        //也就是说该reset报文不是争对此syn的reset报文
        if (!tcp_hdr->f_ack) {
            return NET_ERR_OK; //这里为什么是返回OK?
        }

        //是争对此次syn的reset报文,则终止此次链接,并通知上层应用
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    //正常收到对方发送的syn和ack
    if (tcp_hdr->f_syn) {
        //记录对方的初始序列号, 用处?
        tcp->rcv.iss = tcp_hdr->seq;
        //期望对方下次发过来的第一个字节的序列号,接收到数据时做检查
        tcp->rcv.nxt = tcp_hdr->seq + 1;
        //作用见tcp_transmit
        tcp->flags.irs_valid = 1;

        //如果当前值为0,则说明客户端端和服务端同时发了syn包,因为收到的包ack为0,即第一次握手
        if (tcp_hdr->f_ack) {
            tcp_ack_process(tcp, seg);
        } 

    }

    return NET_ERR_OK;
}
net_err_t tcp_syn_recvd_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_established_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_fin_wait_1_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_fin_wait_2_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_closing_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_time_wait_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_close_wait_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_last_ack_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}