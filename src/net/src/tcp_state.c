#include "tcp_state.h"
#include "tcp_out.h"
#include "tcp_in.h"

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

        if (tcp_hdr->f_ack) {
            //第三次握手
            tcp_send_ack(tcp, seg);
            //通知应用程序,三次握手已经完成,链接建立,并改变链接状态
            tcp_set_state(tcp, TCP_STATE_ESTABLISHED);
            sock_wakeup(&tcp->base, SOCK_WAIT_CONN, NET_ERR_OK);
        } else {
            //四次握手非常难测试,故暂时未测
            //收到syn包的回包时,发现回包位携带ack,即ack为0,
            //那么我方发送syn包的同时,对方也发syn包了,此时走四次握手
            tcp_set_state(tcp, TCP_STATE_SYN_RECVD);
            tcp_send_syn(tcp);
        }
        
    }

    return NET_ERR_OK;
}
net_err_t tcp_syn_recvd_in(tcp_t *tcp, tcp_seg_t *seg) {
    return NET_ERR_OK;
}
net_err_t tcp_established_in(tcp_t *tcp, tcp_seg_t *seg) {
    tcp_hdr_t *tcp_hdr = seg->hdr;

    //如果对方应用程序因为某种原因退出
    if (tcp_hdr->f_rst) {
        dbg_warning(DBG_TCP, "recv a rst");
        //这里最好不要给对方发rst报文,因为对方收到rst报文后,也可能再回rst报文,
        //这样一直发,所以直接终止连接
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    if (tcp_hdr->f_syn) {
        dbg_warning(DBG_TCP, "recv a syn");
        //此时直接回复对方reset,让对方关闭
        tcp_send_reset(seg);
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    if (tcp_ack_process(tcp, seg) < 0) {
        dbg_warning(DBG_TCP, "ack process failed.");
        return NET_ERR_UNREACH;
    }

    tcp_data_in(tcp, seg);

    //切换状态
    if (tcp_hdr->f_fin) {
        tcp_set_state(tcp, TCP_STATE_CLOSE_WAIT);
    }

    return NET_ERR_OK;
}

void tcp_time_wait(tcp_t *tcp) {
    //后面补充其他代码
    tcp_set_state(tcp, TCP_STATE_TIME_WAIT);
}

net_err_t tcp_fin_wait_1_in(tcp_t *tcp, tcp_seg_t *seg) {
    tcp_hdr_t *tcp_hdr = seg->hdr;

    //如果对方应用程序因为某种原因退出
    if (tcp_hdr->f_rst) {
        dbg_warning(DBG_TCP, "recv a rst");
        //这里最好不要给对方发rst报文,因为对方收到rst报文后,也可能再回rst报文,
        //这样一直发,所以直接终止连接
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    if (tcp_hdr->f_syn) {
        dbg_warning(DBG_TCP, "recv a syn");
        //此时直接回复对方reset,让对方关闭
        tcp_send_reset(seg);
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    if (tcp_ack_process(tcp, seg) < 0) {
        dbg_warning(DBG_TCP, "ack process failed.");
        return NET_ERR_UNREACH;
    }

    tcp_data_in(tcp, seg);

    //我方发送fin后,收到对方的ack后(即f_fin不为1),则表明我方的发往对方
    //的通路已关闭,同时切换状态,但是如果f_fin为1,说明对方发了fin,也发了ack
    if (tcp_hdr->f_fin) {
        //需要回复对方ack,这个在tcp_data_in已经回复了
        tcp_time_wait(tcp);
    } else {
        tcp_set_state(tcp, TCP_STATE_FIN_WAIT_2);
    }

    return NET_ERR_OK;
}

net_err_t tcp_fin_wait_2_in(tcp_t *tcp, tcp_seg_t *seg) {
    tcp_hdr_t *tcp_hdr = seg->hdr;

    //如果对方应用程序因为某种原因退出
    if (tcp_hdr->f_rst) {
        dbg_warning(DBG_TCP, "recv a rst");
        //这里最好不要给对方发rst报文,因为对方收到rst报文后,也可能再回rst报文,
        //这样一直发,所以直接终止连接
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    if (tcp_hdr->f_syn) {
        dbg_warning(DBG_TCP, "recv a syn");
        //此时直接回复对方reset,让对方关闭
        tcp_send_reset(seg);
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    if (tcp_ack_process(tcp, seg) < 0) {
        dbg_warning(DBG_TCP, "ack process failed.");
        return NET_ERR_UNREACH;
    }

    tcp_data_in(tcp, seg);

    //我方发送fin后,走到这里,说明对方先发的ack,再发送的fin
    if (tcp_hdr->f_fin) {
        //需要回复对方ack,这个在tcp_data_in已经回复了
        tcp_time_wait(tcp);
    }

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
    //四次挥手的最后一个ack的处理
    tcp_hdr_t *tcp_hdr = seg->hdr;

     //如果对方应用程序因为某种原因退出
    if (tcp_hdr->f_rst) {
        dbg_warning(DBG_TCP, "recv a rst");
        //这里最好不要给对方发rst报文,因为对方收到rst报文后,也可能再回rst报文,
        //这样一直发,所以直接终止连接
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    if (tcp_hdr->f_syn) {
        dbg_warning(DBG_TCP, "recv a syn");
        //此时直接回复对方reset,让对方关闭
        tcp_send_reset(seg);
        return tcp_abort(tcp, NET_ERR_RESET);
    }

    if (tcp_ack_process(tcp, seg) < 0) {
        dbg_warning(DBG_TCP, "ack process failed.");
        return NET_ERR_UNREACH;
    }

    return tcp_abort(tcp, NET_ERR_CLOSE);
}