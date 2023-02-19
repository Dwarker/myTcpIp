#ifndef NETIF_H
#define NETIF_H

#include "ipaddr.h"
#include "nlist.h"
#include "fixq.h"
#include "net_cfg.h"
#include "net_err.h"

//网络接口
typedef struct _netif_hwaddr_t {
    uint8_t addr[NETIF_HWADDR_SIZE];
    uint8_t len;
}netif_haddr_t;

typedef enum _netif_type_t {
    NETIF_TYPE_NONE = 0,
    NETIF_TYPE_ETHER,
    NETIF_TYPE_LOOP,

    NETIF_TYPE_SIZE,
}netif_type_t;

struct _netif_t;
//争对网卡硬件的操作接口
typedef struct _netif_ops_t {
    net_err_t (*open) (struct _netif_t *netif, void *data);
    void (*close) (struct _netif_t *netif);
    net_err_t (*xmit) (struct _netif_t *netif);
}netif_ops_t;

typedef struct _netif_t {
    char name[NETIF_NAME_SIZE];
    netif_haddr_t hwaddr;

    ipaddr_t ipaddr;
    ipaddr_t netmask;
    ipaddr_t gateway;

    netif_type_t type;
    int mtu;

    //网卡状态
    enum {
        NETIF_CLOSED,
        NETIF_OPENED,//相关数据已初始化好,但还不被允许输入输出
        NETIF_ACTIVE,
    }state;

    const netif_ops_t *ops;//正对网卡硬件的接口
    void *ops_data;//配合ops使用(给底层驱动使用)

    nlist_node_t node;//用于链接其他网卡

    fixq_t in_q;    //网卡输入队列
    void *in_q_buf[NETIF_INQ_SIZE];
    fixq_t out_q;   //网卡输出队列
    void *out_q_buf[NETIF_OUTQ_SIZE];
}netif_t;

net_err_t netif_init(void);
netif_t *netif_open(const char *dev_name, const netif_ops_t *ops, void *ops_data);
net_err_t netif_set_addr(netif_t *netif, ipaddr_t *ip, ipaddr_t *netmask, ipaddr_t *gateway);
net_err_t netif_set_hwaddr(netif_t *netif, const char *hwaddr, int len);
#endif