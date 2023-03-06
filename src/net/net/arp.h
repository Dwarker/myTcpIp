#ifndef ARP_H
#define ARP_H

#include "ipaddr.h"
#include "ether.h"
#include "pktbuf.h"

#define ARP_HW_ETHER    1
#define ARP_REQUEST     1
#define ARP_REPLY       2

#pragma pack(1)
typedef struct _arp_pkt_t {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hwlen;
    uint8_t  plen;
    uint16_t opcode;
    uint8_t  sender_hwaddr[ETHER_HWA_SIZE];
    uint8_t  sender_paddr[IPV4_ADDR_SIZE];
    uint8_t  target_hwaddr[ETHER_HWA_SIZE];
    uint8_t  target_paddr[IPV4_ADDR_SIZE];
}arp_pkt_t;

#pragma pack()

typedef struct _arp_entry_t {
    uint8_t paddr[IPV4_ADDR_SIZE];
    uint8_t hwaddr[ETHER_HWA_SIZE];

    enum {
        NET_ARP_FREE,       //当前arp表项数据全部无效
        NET_ARP_WAITING,    //arp包发送后,等待响应状态
        NET_ARP_RESOLVED,   //已经收到arp数据包,硬件地址解析完成
    }state;

    int tmo;
    int retry;

    nlist_node_t node;

    //另外这里的数据包需要进行限制,因为如果应用不停的发送数据,
    //导致内存用尽,会影响别的应用,用宏(ARP_MAX_PKT_WAIT控制)
    nlist_t buf_list;//用来存储链接未发出去的数据包(等收到arp相应包,知道硬件地址后再发送)

    netif_t *netif;  //等硬件地址填入后,数据包通过这个网卡发送出去
}arp_entry_t;

net_err_t arp_init(void);

net_err_t arp_make_request(netif_t *netif, const ipaddr_t *dest);

//无回报ARP
net_err_t arp_make_gratuitous(netif_t *netif);

net_err_t arp_in(netif_t *netif, pktbuf_t *buf);

net_err_t arp_resolve(netif_t *netif, const ipaddr_t *ipaddr, pktbuf_t *buf);

void arp_clear(netif_t *netif);
const uint8_t *arp_find(netif_t *netif, ipaddr_t *ipaddr);
void arp_update_from_ipbuf(netif_t *netif, pktbuf_t *buf);

#endif