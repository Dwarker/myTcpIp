#ifndef EXMSG_H
#define EXMSG_H

#include "net_err.h"
#include "nlist.h"
#include "netif.h"

struct _func_msg_t;
typedef net_err_t (*exmsg_func_t)(struct _func_msg_t *msg);

typedef struct _msg_netif_t {
    netif_t *netif;
}msg_netif_t;

typedef struct _func_msg_t {
    sys_thread_t thread;//也可以不用,这里为了方便调试

    exmsg_func_t func;
    void *param;
    net_err_t err;//执行结果,应用程序会从这里取

    sys_sem_t wait_sem;
}func_msg_t;


typedef struct _exmsg_t {
    nlist_node_t node;
    enum {
        NET_EXMSG_NETIF_IN,
        NET_EXMSG_FUN,
    }type;
    
    union {
        msg_netif_t netif;//表示哪个网卡接收到了消息
        func_msg_t *func;
    };
    
}exmsg_t;

net_err_t exmsg_init(void);
net_err_t exmsg_start(void);
net_err_t exmsg_netif_in(netif_t *netif);
net_err_t exmsg_func_exec(exmsg_func_t func, void *param);
#endif