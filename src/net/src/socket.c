#include "socket.h"
#include "sock.h"
#include "exmsg.h"
#include "dbg.h"

int x_socket(int family, int type, int protocol) {
    sock_req_t req;

    req.wait = (sock_wait_t *)0;
    req.wait_tmo = 0;
    req.sockfd = -1;
    req.create.family = family;
    req.create.protocol = protocol;
    req.create.type = type;

    net_err_t err = exmsg_func_exec(sock_create_req_in, &req);
    if (err < 0) {
        dbg_error(DBG_SOCKET, "create socket failed.");
        return -1;
    }

    return req.sockfd;
}

ssize_t x_sendto(int s, const void* buf, size_t len, int flags, 
                const struct x_sockaddr *dest, x_socklen_t dest_len) {
    if (!buf || !len) {
        dbg_error(DBG_SOCKET, "param error");
        return -1;
    }

    if ((dest->sin_family != AF_INET) || (dest_len != sizeof(struct x_sockaddr_in))) {
        dbg_error(DBG_SOCKET, "param error");
        return -1;
    }

    ssize_t send_size = 0;//计算实际发了多少
    uint8_t *start = (uint8_t *)buf;
    while (len > 0) {
        static sock_req_t req;
        plat_memset(&req, 0, sizeof(sock_req_t));
        req.sockfd = s;
        req.wait = (sock_wait_t *)0;
        req.wait_tmo = 0;
        req.data.buf = start;
        req.data.flags = 0;
        req.data.len = len;
        req.data.addr = (struct x_sockaddr *)dest;
        req.data.addr_len = &dest_len;
        req.data.comp_len = 0;

        net_err_t err = exmsg_func_exec(sock_sendto_req_in, &req);
        if (err < 0) {
            dbg_error(DBG_SOCKET, "sendto socket failed.");
            return -1;
        }

        //tcp发送的时候,可能会等待
        if(req.wait && ((err = sock_wait_enter(req.wait, req.wait_tmo)) < 0)) {
            dbg_error(DBG_SOCKET, "send failed.");
            return -1;
        }

        len -= req.data.comp_len;
        start += req.data.comp_len;
        send_size += (ssize_t)req.data.comp_len;
    }

    return send_size;
}

ssize_t x_recvfrom(int s, void* buf, size_t len, int flags, 
                const struct x_sockaddr *src, x_socklen_t *src_len) {
    if (!buf || !len || !src) {
        dbg_error(DBG_SOCKET, "param error");
        return -1;
    }

    while (1) {
        static sock_req_t req;
        plat_memset(&req, 0, sizeof(sock_req_t));
        req.wait = (sock_wait_t *)0;
        req.wait_tmo = 0;
        req.sockfd = s;
        req.data.buf = buf;
        req.data.flags = 0;
        req.data.len = len;
        req.data.addr = (struct x_sockaddr *)src;
        req.data.addr_len = src_len;
        req.data.comp_len = 0;

        net_err_t err = exmsg_func_exec(sock_recvfrom_req_in, &req);
        if (err < 0) {
            dbg_error(DBG_SOCKET, "recvfrom socket failed:%d.", err);
            return -1;
        }

        if (req.data.comp_len) {
            return (ssize_t)req.data.comp_len;
        }

        //如果没有数据则等待,有数据到了则进入循环再次读取
        err = sock_wait_enter(req.wait, req.wait_tmo);
        if (err < 0) {
            dbg_error(DBG_SOCKET, "recv failed.");
            return -1;
        }
    }
}

int x_setsockopt(int s, int level, int optname, const char *optval, int len) {
    if (!optval || !len) {
        dbg_error(DBG_SOCKET, "param error");
        return -1;
    }

    sock_req_t req;
    req.wait = (sock_wait_t *)0;
    req.wait_tmo = 0;
    req.sockfd = s;
    req.opt.level = level;
    req.opt.optname = optname;
    req.opt.optval = optval;
    req.opt.len = len;

    net_err_t err = exmsg_func_exec(sock_setsockopt_req_in, &req);
    if (err < 0) {
        dbg_error(DBG_SOCKET, "set sockopt failed.");
        return -1;
    }

    return 0;
}

//在某些情况下也需要等,如tcp 等待后面再做
int x_close(int s) {
    sock_req_t req;

    req.wait = (sock_wait_t *)0;
    req.wait_tmo = 0;
    req.sockfd = s;

    net_err_t err = exmsg_func_exec(sock_close_req_in, &req);
    if (err < 0) {
        dbg_error(DBG_SOCKET, "close socket failed.");
        return -1;
    }

    return 0;
}