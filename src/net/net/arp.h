#ifndef ARP_H
#define ARP_H

#include "ipaddr.h"
#include "ether.h"
#include "pktbuf.h"

typedef struct _arp_entry_t {
    uint8_t paddr[IPV4_ADDR_SIZE];
    uint8_t hwaddr[ETHER_HWA_SIZE];

    enum {
        NET_ARP_FREE,       //当前arp表项数据全部无效
        NET_APP_WAITING,    //arp包发送后,等待响应状态
        NET_ARP_RESOLVED,   //已经收到arp数据包,硬件地址解析完成
    }state;

    nlist_node_t node;
    nlist_t buf_list;//用来存储链接未发出去的数据包(等收到arp相应包,知道硬件地址后再发送)

    netif_t *netif;  //等硬件地址填入后,数据包通过这个网卡发送出去
}arp_entry_t;

net_err_t arp_init(void);

#endif