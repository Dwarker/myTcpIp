#include "sock.h"
#include "sys.h"
#include "exmsg.h"
#include "dbg.h"
#include "socket.h"
#include "raw.h"
#include "udp.h"
#include "tools.h"
#include "ipv4.h"
#include "tcp.h"

#define SOCKET_MAX_NR   (RAW_MAX_NR + UDP_MAX_NR + TCP_MAX_NR)

static x_socket_t socket_tbl[SOCKET_MAX_NR];

static int get_index(x_socket_t *socket) {
    return (int)(socket - socket_tbl);
}

static x_socket_t *get_socket(int idx) {
    if ((idx < 0) || (idx >= SOCKET_MAX_NR)) {
        return (x_socket_t *)0;
    }

    return socket_tbl + idx;
}

static x_socket_t *socket_alloc(void) {
    x_socket_t *s = (x_socket_t *)0;

    for (int i = 0; i < SOCKET_MAX_NR; i++) {
        x_socket_t *curr = socket_tbl + i;
        if (curr->state == SOCKET_STATE_FREE) {
            curr->state = SOCKET_STATE_USED;
            s = curr;
            break;
        }
    }

    return s;
}

static void socket_free(x_socket_t *s) {
    s->state = SOCKET_STATE_FREE;
}

net_err_t sock_wait_init(sock_wait_t *wait) {
    wait->waiting = 0;
    wait->err = NET_ERR_OK;
    wait->sem = sys_sem_create(0);

    return wait->sem == SYS_SEM_INVALID ? NET_ERR_SYS : NET_ERR_OK;
}

void sock_wait_destory(sock_wait_t *wait) {
    if (wait->sem != SYS_SEM_INVALID) {
        sys_sem_free(wait->sem);
    }
}
void sock_wait_add(sock_wait_t *wait, int tmo, struct _sock_req_t *req) {
    wait->waiting++;

    req->wait = wait;
    req->wait_tmo = tmo;
}
//应用程序调用
net_err_t sock_wait_enter(sock_wait_t *wait, int tmo) {
    if (sys_sem_wait(wait->sem, tmo) < 0) {
        return NET_ERR_TMO;
    }
    return wait->err;
}
//工作线程调用
void sock_wait_leave(sock_wait_t *wait, net_err_t err) {
    if (wait->waiting > 0) {
        wait->waiting--;
        sys_sem_notify(wait->sem);
        wait->err = err;
    }
}

void sock_wakeup(sock_t *sock, int type, int err) {
    if (type & SOCK_WAIT_CONN) {
        sock_wait_leave(sock->conn_wait, err);
    }

    if (type & SOCK_WAIT_WRITE) {
        sock_wait_leave(sock->snd_wait, err);
    }

    if (type & SOCK_WAIT_READ) {
        sock_wait_leave(sock->rcv_wait, err);
    }
}

net_err_t socket_init(void) {
    plat_memset(socket_tbl, 0, sizeof(socket_tbl));
    return NET_ERR_OK;
}

net_err_t sock_init(sock_t *sock, int family, int protocol, const sock_ops_t *ops) {
    sock->protocol = protocol;
    sock->family = family;
    sock->ops = ops;

    ipaddr_set_any(&sock->local_ip);
    ipaddr_set_any(&sock->remote_ip);
    sock->local_port = 0;
    sock->remote_port = 0;
    sock->err = NET_ERR_OK;
    sock->rcv_tmo = 0;
    sock->snd_tmo = 0;
    nlist_node_init(&sock->node);
    sock->rcv_wait = (sock_wait_t *)0;
    sock->snd_wait = (sock_wait_t *)0;
    sock->conn_wait = (sock_wait_t *)0;
    return NET_ERR_OK;
}

void sock_uninit(sock_t *sock) {
    if (sock->rcv_wait) {
        sock_wait_destory(sock->rcv_wait);
    }

    if (sock->conn_wait) {
        sock_wait_destory(sock->rcv_wait);
    }

    if (sock->snd_wait) {
        sock_wait_destory(sock->rcv_wait);
    }
}

net_err_t sock_create_req_in(struct _func_msg_t *msg) {
    static const struct sock_info_t {
        int protocol;
        sock_t * (*create) (int family, int protocol);
    }sock_tbl[] = {
        [SOCK_RAW] = {.protocol = IPPROTO_ICMP, .create = raw_create,},
        [SOCK_DGRAM] = {.protocol = IPPROTO_UDP, .create = udp_create,},
        [SOCK_STREAM] = {.protocol = IPPROTO_TCP, .create = tcp_create,},
    };
    sock_req_t *req = (sock_req_t *)msg->param;
    sock_create_t *param = &req->create;
    
    x_socket_t *s = socket_alloc();
    if (!s) {
        dbg_error(DBG_SOCKET, "no socket");
        return NET_ERR_MEM;
    }

    //越界检查
    if ((param->type < 0)
        || (param->type >= sizeof(sock_tbl) / sizeof(sock_tbl[0])))
    {
        dbg_error(DBG_SOCKET, "create sock failed.");
        socket_free(s);
        return NET_ERR_PARAM;
    }
    
    const struct sock_info_t *info = sock_tbl + param->type;
    if (param->protocol == 0) {
        param->protocol = info->protocol;//如果没有指定协议,则使用缺省值
    }

    sock_t *sock = info->create(param->family, param->protocol);
    if (!sock) {
        dbg_error(DBG_SOCKET, "create sock failed.");
        socket_free(s);
        return NET_ERR_MEM;
    }

    s->sock = sock;
    req->sockfd = get_index(s);
    return NET_ERR_OK;
}

net_err_t sock_sendto_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    sock_data_t *data = &req->data;
    if (!sock->ops->sendto) {
        dbg_error(DBG_SOCKET, "function not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    net_err_t err = sock->ops->sendto(sock, data->buf, data->len, data->flags,
                        data->addr, *data->addr_len, &data->comp_len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->snd_wait) {
            sock_wait_add(sock->snd_wait, sock->snd_tmo, req);
        }
    }
    return NET_ERR_OK;
}

net_err_t sock_send(struct _sock_t *s, const void *buf, ssize_t len, int flags, ssize_t *result_len) {
    struct x_sockaddr_in dest;
    dest.sin_family = s->family;
    dest.sin_port = x_htons(s->remote_port);//这里原始套接字调用的时候,这个端口为0,本身该套接字也用不到端口号
    ipaddr_to_buf(&s->remote_ip, dest.sin_addr.addr_array);

    return s->ops->sendto(s, buf, len, flags, (const struct x_sockaddr *)&dest, sizeof(dest), result_len);
}

net_err_t sock_send_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    sock_data_t *data = &req->data;
    if (!sock->ops->send) {
        dbg_error(DBG_SOCKET, "function not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    net_err_t err = sock->ops->send(sock, data->buf, data->len, data->flags,
                                     &data->comp_len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->snd_wait) {
            sock_wait_add(sock->snd_wait, sock->snd_tmo, req);
        }
    }
    return NET_ERR_OK;
}

net_err_t sock_recvfrom_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    sock_data_t *data = &req->data;
    if (!sock->ops->recvfrom) {
        dbg_error(DBG_SOCKET, "function not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    net_err_t err = sock->ops->recvfrom(sock, data->buf, data->len, data->flags,
                        data->addr, data->addr_len, &data->comp_len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->rcv_wait) {
            sock_wait_add(sock->rcv_wait, sock->rcv_tmo, req);
        }
    }
    return NET_ERR_OK;
}

net_err_t sock_recv(struct _sock_t *s, void *buf, ssize_t len, int flags, ssize_t *result_len) {
    struct x_sockaddr src;
    x_socklen_t addr_len;

    return s->ops->recvfrom(s, buf, len, flags, &src, &addr_len, result_len);
}

net_err_t sock_recv_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    sock_data_t *data = &req->data;

    if (!sock->ops->recv) {
        dbg_error(DBG_SOCKET, "function not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    net_err_t err = sock->ops->recv(sock, data->buf, data->len, data->flags, &data->comp_len);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->rcv_wait) {
            sock_wait_add(sock->rcv_wait, sock->rcv_tmo, req);
        }
    }
    return err;
}

net_err_t sock_setopt(struct _sock_t *s, int level, int optname, const char* optval, int optlen) {
    if (level != SOL_SOCKET) {
        dbg_error(DBG_SOCKET, "unknow level");
        return NET_ERR_UNKNOWN;
    }

    switch (optname)
    {
    case SO_RCVITIMEO:
    case SO_SNDITIMEO:
        if (optlen != sizeof(struct x_timeval)) {
            dbg_error(DBG_SOCKET, "time size error");
            return NET_ERR_PARAM;
        }

        struct x_timeval *time = (struct x_timeval *)optval;
        int time_ms = time->tv_sec * 1000 + time->tv_usec / 1000;
        //这里的转换不会那么完整,因为后面是除法
        if (optname == SO_RCVITIMEO) {
            s->rcv_tmo = time_ms;
            return NET_ERR_OK;
        } else if (optname == SO_SNDITIMEO) {
            s->snd_tmo = time_ms;
            return NET_ERR_OK;
        } else {
            return NET_ERR_UNKNOWN;
        }
    default:
        break;
    }

    return NET_ERR_UNKNOWN;
}

net_err_t sock_setsockopt_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    sock_opt_t *opt = (sock_opt_t *)&req->opt;
    return sock->ops->setopt(sock, opt->level, opt->optname, opt->optval, opt->len);
}

net_err_t sock_close_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    
    if (!sock->ops->close) {
        dbg_error(DBG_SOCKET, "function not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    net_err_t err = sock->ops->close(sock);
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->conn_wait) {
            sock_wait_add(sock->conn_wait, sock->rcv_tmo, req);
        }
    }

    socket_free(s);
    return err;
}

net_err_t sock_connect_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    if (!sock->ops->connect) {
        dbg_error(DBG_SOCKET, "function not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    sock_conn_t *conn = &req->conn;
    net_err_t err = sock->ops->connect(sock, conn->addr, conn->addr_len);
    //这里等待暂时用不到,tcp的时候会用到
    if (err == NET_ERR_NEED_WAIT) {
        if (sock->conn_wait) {
            sock_wait_add(sock->conn_wait, sock->rcv_tmo, req);
        }
    }

    return NET_ERR_OK;
}

net_err_t sock_bind_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    if (!sock->ops->connect) {
        dbg_error(DBG_SOCKET, "function not imp");
        return NET_ERR_NOT_SUPPORT;
    }

    sock_bind_t *bind = &req->bind;
    return sock->ops->bind(sock, bind->addr, bind->addr_len);
}

net_err_t sock_connect(sock_t *sock, const struct x_sockaddr* addr, x_socklen_t len) {
    struct x_sockaddr_in *remote = (struct x_sockaddr_in *)addr;
    ipaddr_from_buf(&sock->remote_ip, remote->sin_addr.addr_array);
    sock->remote_port = x_ntohs(remote->sin_port);
    return NET_ERR_OK;
}

net_err_t sock_bind(sock_t *sock, const struct x_sockaddr* addr, x_socklen_t len) {
    ipaddr_t local_ip;
    struct x_sockaddr_in *local = (struct x_sockaddr_in *)addr;
    ipaddr_from_buf(&local_ip, local->sin_addr.addr_array);

    if (!ipaddr_is_any(&local_ip)) {
        rentry_t *rt = rt_find(&local_ip);
        //这里的后半部分比较其实可以删掉,在rt_find中已经做了
        if (!rt || (!ipaddr_is_equal(&rt->netif->ipaddr, &local_ip))) {
            dbg_error(DBG_SOCKET, "addr error");
            return NET_ERR_PARAM;
        }
    }

    ipaddr_copy(&sock->local_ip, &local_ip);
    sock->local_port = x_ntohs(local->sin_port);

    return NET_ERR_OK;
}

net_err_t sock_listen_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    sock_listen_t *listen = &req->listen;
    return sock->ops->listen(sock, listen->backlog);
}

net_err_t sock_accept_req_in(struct _func_msg_t *msg) {
    sock_req_t *req = (sock_req_t *)msg->param;

    x_socket_t *s = get_socket(req->sockfd);
    if (!s) {
        dbg_error(DBG_SOCKET, "param error");
        return NET_ERR_PARAM;
    }

    sock_t *sock = s->sock;
    sock_accept_t *accept = &req->accept;

    if (!sock->ops->accept) {
        return NET_ERR_NOT_SUPPORT;
    }

    sock_t *client = (sock_t *)0;
    net_err_t err = sock->ops->accept(sock, accept->addr, accept->len, &client);
    if (err < 0) {
        dbg_error(DBG_SOCKET, "accept error.");
        return err;
    } else if (err == NET_ERR_NEED_WAIT) {
        if (sock->conn_wait) {
            sock_wait_add(sock->conn_wait, sock->rcv_tmo, req);
        }
    } else {
        x_socket_t *child_socket = socket_alloc();
        if (child_socket == (x_socket_t *)0) {
            dbg_error(DBG_SOCKET, "no socket.");
            return NET_ERR_NONE;
        }
        
        child_socket->sock = client;
        accept->client = get_index(child_socket);
    }

    return NET_ERR_OK;
}