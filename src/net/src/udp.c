#include "udp.h"
#include "dbg.h"
#include "mblock.h"
#include "tools.h"
#include "socket.h"
#include "protocol.h"

static udp_t udp_tbl[UDP_MAX_NR];
static mblock_t udp_mblock;
static nlist_t udp_list;

#if DBG_DISP_ENABLED(DBG_UDP)
static void display_udp_packet(udp_pkt_t *pkt) {
    plat_printf("udp packet:\n");
    plat_printf("   sport: %d\n", pkt->hdr.src_port);
    plat_printf("   dport: %d\n", pkt->hdr.dest_port);
    plat_printf("   len:  %d\n", pkt->hdr.total_len);
    plat_printf("   checksum: %d\n", pkt->hdr.checksum);
}
static void display_udp_list(void) {
    plat_printf("------- udp list -------\n");

    nlist_node_t *node;
    int idx = 0;
    nlist_for_each(node, &udp_list) {
        udp_t *udp = (udp_t *)nlist_entry(node, sock_t, node);
        plat_printf("[%d]:\n", idx++);
        dbg_dump_ip("   local:", &udp->base.local_ip);
        plat_printf("   local port: %d, ", udp->base.local_port);
        dbg_dump_ip("   remote:", &udp->base.remote_ip);
        plat_printf("   remote port: %d", udp->base.remote_port);
        plat_printf("\n");
    }
}
#else
#define display_udp_packet(packet)
#define display_udp_list()
#endif

net_err_t udp_init(void) {
    dbg_info(DBG_UDP, "udp init");

    nlist_init(&udp_list);
    mblock_init(&udp_mblock, udp_tbl, sizeof(udp_t), UDP_MAX_NR, NLOCKER_NONE);
    dbg_info(DBG_UDP, "done");
    return NET_ERR_OK;
}

static int is_port_used(int port) {
    nlist_node_t *node;
    nlist_for_each(node, &udp_list) {
        sock_t *sock = (sock_t *)nlist_entry(node, sock_t, node);
        if (sock->local_port == port) {
            return 1;
        }
    }
    return 0;
}

static net_err_t alloc_port(sock_t *sock) {
    static int search_index = NET_PORT_DYN_START;
    for (int i = NET_PORT_DYN_START; i < NET_PORT_DYN_END; i++) {
        int port = search_index++;
        if (search_index > NET_PORT_DYN_END) {
            search_index = NET_PORT_DYN_START;
        }
        if (!is_port_used(port)) {
            sock->local_port = port;
            return NET_ERR_OK;
        }
    }

    return NET_ERR_NONE;
}

static net_err_t udp_sendto (struct _sock_t *s, const void *buf, ssize_t len, int flags,
                        const struct x_sockaddr *dest, x_socklen_t dest_len, ssize_t *result_len) {
    ipaddr_t dest_ip;
    struct x_sockaddr_in *addr = (struct x_sockaddr_in *)dest;
    ipaddr_from_buf(&dest_ip, addr->sin_addr.addr_array);
    uint16_t dport = x_ntohs(addr->sin_port);
    if (!ipaddr_is_any(&s->remote_ip) && !ipaddr_is_equal(&dest_ip, &s->remote_ip)) {
        dbg_error(DBG_RAW, "dest is incorrect");
        return NET_ERR_PARAM;
    }

    if (s->remote_port && (s->remote_port != dport)) {
        dbg_error(DBG_UDP, "dest is incorrect");
        return NET_ERR_PARAM;
    }

    //端口分配
    if (!s->local_port && ((s->err = alloc_port(s)) < 0)) {
        dbg_error(DBG_UDP, "no port avaliable");
        return NET_ERR_NONE;
    }

    pktbuf_t *pktbuf = pktbuf_alloc((int)len);
    if (!pktbuf) {
        dbg_error(DBG_SOCKET, "no buffer.");
        return NET_ERR_MEM;
    }

    net_err_t err = pktbuf_write(pktbuf, (uint8_t *)buf, (int)len);
    if (err < 0) {
        dbg_error(DBG_RAW, "copy data error");
        goto end_send_to;
    }
    
    //这里local_ip可能为空,则在ip层中会选择合适的网卡发送
    err = udp_out(&dest_ip, dport, &s->local_ip, s->local_port, pktbuf);
    if (err < 0) {
        dbg_error(DBG_UDP, "send error");
        goto end_send_to;
    }

    *result_len = (ssize_t)len;

    return NET_ERR_OK;
end_send_to:
    pktbuf_free(pktbuf);
    return err;
}


static net_err_t udp_recvfrom (struct _sock_t *s, void *buf, ssize_t len, int flags,
                        struct x_sockaddr *src, x_socklen_t *src_len, ssize_t *result_len) {
    udp_t *udp = (udp_t *)s;

    nlist_node_t *first = nlist_remove_first(&udp->recv_list);
    if (!first) {
        //告诉上层应用程序,数据还没到,需要等待
        *result_len = 0;
        return NET_ERR_NEED_WAIT;
    }
    
    //
    pktbuf_t *pktbuf = nlist_entry(first, pktbuf_t, node);
    udp_from_t *from = (udp_from_t *)pktbuf_data(pktbuf);

    struct x_sockaddr_in * addr = (struct x_sockaddr_in *)src;
    plat_memset(addr, 0, sizeof(struct x_sockaddr_in));
    addr->sin_family = AF_INET; //只支持IP4
    addr->sin_port = x_htons(from->port);
    ipaddr_to_buf(&from->from, addr->sin_addr.addr_array);

    //移除IP+port头部
    pktbuf_remove_header(pktbuf, sizeof(udp_from_t));

    //读取数据
    int size = (pktbuf->total_size > (int)len) ? (int)len : pktbuf->total_size;
    pktbuf_reset_acc(pktbuf);

    net_err_t err = pktbuf_read(pktbuf, buf, size);
    if (err < 0) {
        pktbuf_free(pktbuf);
        dbg_error(DBG_RAW, "pktbuf read error");
        return err;
    }

    pktbuf_free(pktbuf);
    *result_len = size;
    return NET_ERR_OK;
}

net_err_t udp_close(sock_t *sock) {
    udp_t *udp = (udp_t *)sock;

    nlist_remove(&udp_list, &sock->node);

    nlist_node_t *node;
    while ((node = nlist_remove_first(&udp->recv_list))) {
        pktbuf_t *buf = nlist_entry(node, pktbuf_t, node);
        pktbuf_free(buf);
    }

    sock_uninit(sock);

    mblock_free(&udp_mblock, sock);

    display_udp_list();

    return NET_ERR_OK;
}

net_err_t udp_connect(struct _sock_t *s, const struct x_sockaddr *addr, x_socklen_t addr_len) {
    sock_connect(s, addr, addr_len);
    display_udp_list();
    return NET_ERR_OK;
}

sock_t *udp_create(int family, int protocol) {
    static const sock_ops_t udp_ops = {
        .setopt = sock_setopt,
        .sendto = udp_sendto,
        .recvfrom = udp_recvfrom,
        .close = udp_close,
        .connect = udp_connect,
        .send = sock_send,
        .recv = sock_recv,
    };

    udp_t *udp = mblock_alloc(&udp_mblock, -1);
    if (!udp) {
        dbg_error(DBG_UDP, "no udp sock");
        return (sock_t *)0;
    }

    net_err_t err = sock_init((sock_t *)udp, family, protocol, &udp_ops);
    if (err < 0) {
        dbg_error(DBG_UDP, "create udp failed.");
        mblock_free(&udp_mblock, udp);
        return (sock_t *)0;
    }

    //接收到数据后,会将数据报挂载在recv_list中
    nlist_init(&udp->recv_list);

    udp->base.rcv_wait = &udp->recv_wait; //数据报挂载在recv_list后,再唤醒在recv_wait上等待的套接字
    if (sock_wait_init(udp->base.rcv_wait) < 0) {
        dbg_error(DBG_UDP, "create rcv wait failed.");
        goto create_failed;
    }

    nlist_insert_last(&udp_list, &udp->base.node);
    
    display_udp_list();
    return (sock_t *)udp;

create_failed:
    sock_uninit(&udp->base);
    return (sock_t *)0;
}

net_err_t udp_out(ipaddr_t *dest, uint16_t dport, ipaddr_t *src, uint16_t sport, pktbuf_t *buf) {
    if (ipaddr_is_any(src)) {
        rentry_t *rt = rt_find(dest);
        if (rt == (rentry_t *)0) {
            dbg_error(DBG_UDP, "no route");
            return NET_ERR_UNREACH;
        }

        src = &rt->netif->ipaddr;
    }
    
    net_err_t err = pktbuf_add_header(buf, sizeof(udp_hdr_t), 1);
    if (err < 0) {
        dbg_error(DBG_UDP, "add header failed.");
        return NET_ERR_SIZE;
    }

    udp_hdr_t *udp_hdr = (udp_hdr_t *)pktbuf_data(buf);
    udp_hdr->checksum = 0;//先默认为0
    udp_hdr->src_port = x_htons(sport);
    udp_hdr->dest_port = x_htons(dport);
    udp_hdr->total_len = x_htons(buf->total_size);
    udp_hdr->checksum = checksum_peso(buf, dest, src, NET_PROTOCOL_UDP); //校验和为0的情况下,对端不用校验校验和

    err = ipv4_out(NET_PROTOCOL_UDP, dest, src, buf);
    if (err < 0) {
        dbg_error(DBG_UDP, "udp out err");
        return err;
    }

    return NET_ERR_OK;
}

static udp_t *udp_find(ipaddr_t *src_ip, uint16_t sport, ipaddr_t *dest_ip, uint16_t dport) {
    if (!dport) {
        return (udp_t *)0;
    }

    nlist_node_t *node;
    nlist_for_each(node, &udp_list) {
        sock_t *s = nlist_entry(node, sock_t, node);
        if (s->local_port != dport) {
            continue;
        }

        if (!ipaddr_is_any(&s->local_ip) && !ipaddr_is_equal(dest_ip, &s->local_ip)) {
            continue;
        }

        if (!ipaddr_is_any(&s->remote_ip) && !ipaddr_is_equal(src_ip, &s->remote_ip)) {
            continue;
        }

        if (s->remote_port && (s->remote_port != sport)) {
            continue;
        }
        return (udp_t *)s;
    }

    return (udp_t *)0;
}

static net_err_t is_pkt_ok(udp_pkt_t *pkt, int size) {
    if ((size < sizeof(udp_hdr_t)) && (size < pkt->hdr.total_len)) {
        dbg_warning(DBG_UDP, "udp packet size error.");
        return NET_ERR_SIZE;
    }

    return NET_ERR_OK;
}

net_err_t udp_in(pktbuf_t *buf, ipaddr_t *src_ip, ipaddr_t *dest_ip) {
    int iphdr_size = ipv4_hdr_size((ipv4_pkt_t *)pktbuf_data(buf));

    net_err_t err = pktbuf_set_cont(buf, sizeof(udp_hdr_t) + iphdr_size);
    if (err < 0) {
        dbg_error(DBG_UDP, "set udp cont failed.");
        return err;
    }

    udp_pkt_t *udp_pkt = (udp_pkt_t *)((pktbuf_data(buf) + iphdr_size));
    uint16_t local_port = x_ntohs(udp_pkt->hdr.dest_port);
    uint16_t remote_port = x_ntohs(udp_pkt->hdr.src_port);

    //找到合适的udp结构(即对应的应用程序)
    //src_ip, remote_port:发送方  dest_ip, local_port:接收方
    udp_t *udp = (udp_t *)udp_find(src_ip, remote_port, dest_ip, local_port);
    if (!udp) {
        dbg_error(DBG_UDP, "no udp for packet.");
        return NET_ERR_UNREACH;
    }

    //移除IP包头
    pktbuf_remove_header(buf, iphdr_size);
    udp_pkt = (udp_pkt_t *)pktbuf_data(buf);
    if (udp_pkt->hdr.checksum) {
        pktbuf_reset_acc(buf);
        if (checksum_peso(buf, dest_ip, src_ip, NET_PROTOCOL_UDP)) {
            dbg_warning(DBG_UDP, "udp check sum failed.");
            return NET_ERR_BROKEN;
        }
    }

    udp_pkt->hdr.src_port = x_ntohs(udp_pkt->hdr.src_port);
    udp_pkt->hdr.dest_port = x_ntohs(udp_pkt->hdr.dest_port);
    udp_pkt->hdr.total_len = x_ntohs(udp_pkt->hdr.total_len);
    if((err = is_pkt_ok(udp_pkt, buf->total_size)) < 0) {
        dbg_warning(DBG_UDP, "udp packet error");
        return err;
    }

    //移除UDP头部(保留来源的ip地址和端口)
    pktbuf_remove_header(buf, sizeof(udp_hdr_t) - sizeof(udp_from_t));
    udp_from_t *from = (udp_from_t *)pktbuf_data(buf);
    from->port = remote_port;
    ipaddr_copy(&from->from, src_ip);
    if (nlist_count(&udp->recv_list) < UDP_MAX_RECV) {
        nlist_insert_last(&udp->recv_list, &buf->node);
        sock_wakeup((sock_t *)udp, SOCK_WAIT_READ, NET_ERR_OK);
    } else {
        pktbuf_free(buf);
    }

    return NET_ERR_OK;
}