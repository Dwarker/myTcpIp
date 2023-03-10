#ifndef SOCK_H
#define SOCK_H

#include "net_err.h"
#include "nlist.h"
#include "sys.h"
#include "ipaddr.h"

struct _sock_t;
typedef int x_socklen_t;
struct x_sockaddr;

typedef struct _sock_ops_t {
    net_err_t (*close) (struct _sock_t *s);
    net_err_t (*sendto) (struct _sock_t *s, const void *buf, ssize_t len, int flags,
                        const struct x_sockaddr *dest, x_socklen_t dest_len, ssize_t *result_len);
    net_err_t (*recvfrom) (struct _sock_t *s, void *buf, ssize_t len, int flags,
                        const struct x_sockaddr *dest, x_socklen_t dest_len, ssize_t *result_len);
    net_err_t (*setopt) (struct _sock_t *s, int level, int optname, const char* optval, int optlen);
    void (*destory) (struct _sock_t *s);
}sock_ops_t;

typedef struct _sock_t {
    uint16_t local_port;
    ipaddr_t local_ip;
    ipaddr_t remote_ip;
    uint16_t remote_port;

    const sock_ops_t *ops;

    int family;
    int protocol;

    int err;    //ops中回调函数的返回值存放
    int rcv_tmo;   //ping命令的收超时
    int snd_tmo;   //tcp的send(用户态接口)发送超时,

    nlist_node_t node;
}sock_t;

typedef struct _x_socket_t
{
    enum {
        SOCKET_STATE_FREE,
        SOCKET_STATE_USED,
    }state;
}x_socket_t;

typedef struct _sock_create_t {
    int family;
    int type;
    int protocol;
}sock_create_t;

typedef struct _sock_req_t {
    int sockfd;
    union {
        sock_create_t create;
    };
    
}sock_req_t;

net_err_t socket_init(void);
net_err_t sock_create_req_in(struct _func_msg_t *msg);
net_err_t sock_init(sock_t *sock, int family, int protocol, const sock_ops_t *ops);

#endif