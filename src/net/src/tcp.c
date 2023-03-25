#include "tcp.h"
#include "dbg.h"
#include "mblock.h"
#include "socket.h"
#include "protocol.h"
#include "tools.h"
#include "tcp_out.h"

static tcp_t tcp_tbl[TCP_MAX_NR];
static mblock_t tcp_mblock;
static nlist_t tcp_list;
#if DBG_DISP_ENABLED(DBG_TCP)
void tcp_show_info(char *msg, tcp_t *tcp) {
    plat_printf("%s\n", msg);
    plat_printf("local port: %d, remote port: %d\n", tcp->base.local_port, tcp->base.remote_port);
}

void tcp_show_pkt(char *msg, tcp_hdr_t *tcp_hdr, pktbuf_t *buf) {
    plat_printf("%s\n", msg);
    plat_printf("   sport: %u, dport: %u\n", tcp_hdr->sport, tcp_hdr->dport);
    plat_printf("   seq: %u, ack: %u, win: %u\n", tcp_hdr->seq, tcp_hdr->ack, tcp_hdr->win);
    plat_printf("   flags:");
    if (tcp_hdr->f_syn) {
        plat_printf(" syn");
    }
    if (tcp_hdr->f_rst) {
        plat_printf(" rst");
    }
    if (tcp_hdr->f_ack) {
        plat_printf(" ack");
    }
    if (tcp_hdr->f_psh) {
        plat_printf(" psh");
    }
    if (tcp_hdr->f_fin) {
        plat_printf(" fin");
    }
    plat_printf("\n    len=%d\n", buf->total_size - tcp_hdr_size(tcp_hdr));
}
void tcp_show_list(void) {
    plat_printf("----tcp list----\n");

    nlist_node_t *node;
    nlist_for_each(node, &tcp_list) {
        tcp_t *tcp = (tcp_t *)nlist_entry(node, sock_t, node);
        tcp_show_info("", tcp);
    }
}
#endif

net_err_t tcp_init(void) {
    dbg_info(DBG_TCP, "tcp init.");

    nlist_init(&tcp_list);
    mblock_init(&tcp_mblock, tcp_tbl, sizeof(tcp_t), TCP_MAX_NR, NLOCKER_NONE);

    dbg_info(DBG_TCP, "init done.");
    return NET_ERR_OK;
}

static tcp_t *tcp_get_free(int wait) {
    tcp_t *tcp = mblock_alloc(&tcp_mblock, wait ? 0 : -1);
    if (!tcp) {
        dbg_error(DBG_TCP, "no tcp sock.");
        return (tcp_t *)0;
    }

    return tcp;
}

int tcp_alloc_port(void) {
#if 1
    srand((unsigned int)time(NULL));
    int search_idx = rand() % 1000 + NET_PORT_DYN_START;
#else
    static int search_idx = NET_PORT_DYN_START;
#endif
    for (int i = NET_PORT_DYN_START; i < NET_PORT_DYN_END; i++) {
        nlist_node_t *node;
        nlist_for_each(node, &tcp_list) {
            sock_t *sock = nlist_entry(node, sock_t, node);
            //被使用了
            if (sock->local_port == search_idx) {
                break;
            }
        }

        if (++search_idx >= NET_PORT_DYN_END) {
            search_idx = NET_PORT_DYN_START;
        }

        //没有被使用的情况下,node应该为空
        if (!node) {
            return search_idx;
        }
    }

    return -1;
}

static uint32_t tcp_get_iss(void) {
    static uint32_t seq = 0;

    return ++seq;
}

static net_err_t tcp_init_connect(tcp_t *tcp) {
    tcp->snd.iss = tcp_get_iss();
    tcp->snd.una = tcp->snd.nxt = tcp->snd.iss;

    //还没接收到服务端的数据,所以直接填0
    tcp->rcv.nxt = 0;
    return NET_ERR_OK;
}

net_err_t tcp_connect(struct _sock_t *s, const struct x_sockaddr *addr, x_socklen_t addr_len) {
    tcp_t *tcp = (tcp_t *)s;
    const struct x_sockaddr_in *addr_in = (const struct x_sockaddr_in *)addr;

    ipaddr_from_buf(&s->remote_ip, (uint8_t *)&addr_in->sin_addr.s_addr);
    s->remote_port = x_ntohs(addr_in->sin_port);

    //本地的ip和port,客户端也可以用bind进行绑定,但是一般不用
    if (s->local_port == NET_PORT_EMPTY) {
        int port = tcp_alloc_port();
        if (port == -1) {
            dbg_error(DBG_TCP, "alloc port failed.");
            return NET_ERR_NONE;
        }

        s->local_port = port;
    }

    //这里ip地址不设置的话,实际上会在ipv4_out里面会选择一个合适的ip
    //也可以在这里进行选择:根据对方的IP查路由表,找到下一跳的地址
    //但是也有个问题,如果之前选择的网卡被禁用或者换了一个ip,
    //那么下一次发送的时候,就会发送不了
    if (ipaddr_is_any(&s->local_ip)) {
        rentry_t *rt = rt_find(&s->remote_ip);
        if (rt == (rentry_t *)0) {
            dbg_error(DBG_TCP, "no route to host.");
            return NET_ERR_UNREACH;
        }

        ipaddr_copy(&s->local_ip, &rt->netif->ipaddr);
    }

    net_err_t err = NET_ERR_OK;
    if (tcp_init_connect(tcp) < 0) {
        dbg_error(DBG_TCP, "init conn failed.");
        return err;
    }

    if (err = tcp_send_syn(tcp) < 0) {
        dbg_error(DBG_TCP, "send syn failed.");
        return err;
    }

    //client发送syn包后,需要等待,但是这里是工作线程,相当于内核,
    //不能让内核卡死,所以范围WAIT值,让应用程序进行等待
    return NET_ERR_NEED_WAIT;
}

net_err_t tcp_close(struct _sock_t *s) {
    return NET_ERR_OK;
}

static tcp_t *tcp_alloc(int wait, int family, int protocol) {
    static const sock_ops_t tcp_ops = {
        .connect = tcp_connect,
        .close = tcp_close,
    };

    tcp_t *tcp = tcp_get_free(wait);
    if (!tcp) {
        dbg_error(DBG_TCP, "no tcp sock.");
        return (tcp_t *)0;
    }

    plat_memset(tcp, 0, sizeof(tcp_t));

    net_err_t err = sock_init((sock_t *)tcp, family, protocol, &tcp_ops);
    if (err < 0) {
        dbg_error(DBG_TCP, "sock init failed.");
        mblock_free(&tcp_mblock, tcp);
        return (tcp_t *)0;
    }

    if (sock_wait_init(&tcp->conn.wait) < 0) {
        dbg_error(DBG_TCP, "create conn.wait failed.");
        goto alloc_failed;
    }
    tcp->base.conn_wait = &tcp->conn.wait;

    if (sock_wait_init(&tcp->snd.wait) < 0) {
        dbg_error(DBG_TCP, "create snd.wait failed.");
        goto alloc_failed;
    }
    tcp->base.snd_wait = &tcp->snd.wait;

    if (sock_wait_init(&tcp->rcv.wait) < 0) {
        dbg_error(DBG_TCP, "create rcv.wait failed.");
        goto alloc_failed;
    }
    tcp->base.rcv_wait = &tcp->rcv.wait;

    return tcp;

alloc_failed:
    if (tcp->base.conn_wait) {
        sock_wait_destory(tcp->base.conn_wait);
    }
    if (tcp->base.snd_wait) {
        sock_wait_destory(tcp->base.snd_wait);
    }
    if (tcp->base.rcv_wait) {
        sock_wait_destory(tcp->base.rcv_wait);
    }
    mblock_free(&tcp_mblock, tcp);
    return (tcp_t *)0;
}

static void tcp_insert(tcp_t *tcp) {
    nlist_insert_last(&tcp_list, &tcp->base.node);

    dbg_assert(tcp_list.count <= TCP_MAX_NR, "tcp count err");
}

sock_t *tcp_create(int family, int protocol) {
    tcp_t *tcp = tcp_alloc(1, family, protocol);
    if (!tcp) {
        dbg_error(DBG_TCP, "alloc tcp failed.");
        return (sock_t *)0;
    }

    tcp_insert(tcp);
    return (sock_t *)tcp;
}