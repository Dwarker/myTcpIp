#include "tcp_state.h"
#include "tcp_out.h"
#include "tcp_in.h"
#include "tools.h"

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
    if (seg->hdr->f_rst == 0) {
        tcp_send_reset(seg);
    }
    return NET_ERR_OK;
}
net_err_t tcp_listen_in(tcp_t *tcp, tcp_seg_t *seg) {
    tcp_hdr_t *tcp_hdr = seg->hdr;
    if (tcp_hdr->f_rst) {
        return NET_ERR_OK;
    }

    if (tcp_hdr->f_ack) {
        tcp_send_reset(seg);
        return NET_ERR_OK;
    }

    if (tcp_hdr->f_syn) {
        if (tcp_backlog_count(tcp) >= tcp->conn.backlog) {
            dbg_warning(DBG_TCP, "queue full.");
            return NET_ERR_FULL;
        }

        tcp_t *child = tcp_create_child(tcp, seg);
        if (child == (tcp_t *)0) {
            dbg_error(DBG_TCP, "no tcp");
            return NET_ERR_MEM;
        }

        tcp_send_syn(child);
        tcp_set_state(child, TCP_STATE_SYN_RECVD);
        return NET_ERR_OK;
    }
    return NET_ERR_UNKNOWN;
}

void tcp_read_option(tcp_t *tcp, tcp_hdr_t * tcp_hdr) {
    uint8_t *opt_start = (uint8_t *)tcp_hdr + sizeof(tcp_hdr_t);
    uint8_t *opt_end = opt_start + (tcp_hdr_size(tcp_hdr) - sizeof(tcp_hdr_t));

    // 无选项则退出
    if (opt_end <= opt_start){
        return;
    }

    // 遍历选项区域，做不同的处理
    while (opt_start < opt_end) {
        tcp_opt_mss_t * opt = (tcp_opt_mss_t *)opt_start;

        switch (opt_start[0]) {
            case TCP_OPT_MSS: {
                // 读取MSS选项，取比较小
                if (opt->length == 4) {
                    uint16_t mss = x_ntohs(opt->mss);
                    if (tcp->mss > mss) {
                        tcp->mss = mss;     // 取最较的值
                    }
                    opt_start += opt->length;
                } else {
                    opt_start++;
                }
                break;
            }
            case TCP_OPT_NOP: {
                // 跳过，进入下一选项处理
                opt_start++;
                break;
            }
            case TCP_OPT_END: {
                // 结束整个循环
                return;
            }
            default: {
                opt_start += opt->length;
                break;
            }
        }
    }
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

        //读取mss值
        tcp_read_option(tcp, tcp_hdr);

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

    //收到ack后,看是否有数据需要传输
    tcp_transmit(tcp);

    //切换状态
    if (tcp->flags.fin_in) {
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

    //主动关闭的时候,也应看下是否缓冲区有数据需要发送
    tcp_transmit(tcp);

    if (tcp->flags.fin_out == 0) {
        //我方发送fin后,收到对方的ack后(即f_fin不为1),则表明我方的发往对方
        //的通路已关闭,同时切换状态,但是如果f_fin为1,说明对方发了fin,也发了ack
        if (tcp->flags.fin_in) {
            //需要回复对方ack,这个在tcp_data_in已经回复了
            tcp_time_wait(tcp);
        } else {
            tcp_set_state(tcp, TCP_STATE_FIN_WAIT_2);
        }
    } else if (tcp->flags.fin_in){
        //两边同时关闭的情况
        tcp_set_state(tcp, TCP_STATE_CLOSING);
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
    if (tcp->flags.fin_in) {
        //需要回复对方ack,这个在tcp_data_in已经回复了
        tcp_time_wait(tcp);
    }

    return NET_ERR_OK;
}
net_err_t tcp_closing_in(tcp_t *tcp, tcp_seg_t *seg) {
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

    //这里不需要再调用tcp_data_in,因为处于time_wait,发送通道已经关闭
    //所以不可能再有业务数据过来
    //tcp_data_in(tcp, seg);

    tcp_transmit(tcp);

    if (tcp->flags.fin_out == 0) {
        tcp_time_wait(tcp);
    }

    return NET_ERR_OK;
}
net_err_t tcp_time_wait_in(tcp_t *tcp, tcp_seg_t *seg) {
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

    //这里不需要再调用tcp_data_in,因为处于time_wait,发送通道已经关闭
    //所以不可能再有业务数据过来
    //tcp_data_in(tcp, seg);

    //time_wait下,收到对方重传的fin包(第三次挥手包)
    if (tcp->flags.fin_in) {
        tcp_send_ack(tcp, seg);
        tcp_time_wait(tcp);
    }

    return NET_ERR_OK;
}

//这个状态下,只是关闭了对方发我方的通道,我方发往对方的还未关闭,所以还可以发送数据
net_err_t tcp_close_wait_in(tcp_t *tcp, tcp_seg_t *seg) {
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

    //单向发往对方
    tcp_transmit(tcp);

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

    //lastack状态还是可以发送的,因为主动close的时候,
    //关闭的是应用程序发往缓存的通道,缓存从网卡发出去并没有关闭
    //所以这里最后看下是否还有数据,有则发送
    tcp_transmit(tcp);

    //如果收到了对方发送的最后一次挥手的ack,那么在tcp_ack_process中,fin_out会置0
    if (tcp->flags.fin_out == 0) {
        return tcp_abort(tcp, NET_ERR_CLOSE);
    }
    return NET_ERR_OK;
}