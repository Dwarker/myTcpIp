#include "udp.h"
#include "dbg.h"
#include "mblock.h"
#include "tools.h"
#include "socket.h"
#include "protocol.h"

static udp_t udp_tbl[UDP_MAX_NR];
static mblock_t udp_mblock;
static nlist_t udp_list;

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

    if (s->remote_port && (s->remote_port == dport)) {
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

sock_t *udp_create(int family, int protocol) {
    static const sock_ops_t udp_ops = {
        .setopt = sock_setopt,
        .sendto = udp_sendto,
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
    
    //display_udp_list();
    return (sock_t *)udp;

create_failed:
    sock_uninit(&udp->base);
    return (sock_t *)0;
}

net_err_t udp_out(ipaddr_t *dest, uint16_t dport, ipaddr_t *src, uint16_t sport, pktbuf_t *buf) {
    net_err_t err = pktbuf_add_header(buf, sizeof(udp_hdr_t), 1);
    if (err < 0) {
        dbg_error(DBG_UDP, "add header failed.");
        return NET_ERR_SIZE;
    }

    udp_hdr_t *udp_hdr = (udp_hdr_t *)pktbuf_data(buf);
    udp_hdr->src_port = x_htons(sport);
    udp_hdr->dest_port = x_htons(dport);
    udp_hdr->total_len = x_htons(buf->total_size);
    udp_hdr->checksum = 0; //后面计算(校验和为0的情况下,对端不用校验校验和)

    err = ipv4_out(NET_PROTOCOL_UDP, dest, src, buf);
    if (err < 0) {
        dbg_error(DBG_UDP, "udp out err");
        return err;
    }

    return NET_ERR_OK;
}