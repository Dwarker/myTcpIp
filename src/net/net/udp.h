#ifndef UDP_H
#define UDP_H

#include "sock.h"

typedef struct _udp_t {
    sock_t base;

    nlist_t recv_list;  //网卡数据收上来后放到这里,唤醒应用程序去取
    sock_wait_t recv_wait;
}udp_t;

net_err_t udp_init(void);

#endif