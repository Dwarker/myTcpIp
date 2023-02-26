#include "arp.h"
#include "dbg.h"
#include "mblock.h"
#include "tools.h"
#include "pktbuf.h"
#include "protocol.h"

static arp_entry_t cache_tbl[ARP_CACHE_SIZE];
static mblock_t cache_mblock;//用于对cache_tbl的分配
static nlist_t cache_list;//存放正在arp查询或者已经查询的arp

//arp缓存表的初始化
static net_err_t cache_init(void) {
    nlist_init(&cache_list);
    net_err_t err = mblock_init(&cache_mblock, cache_tbl, sizeof(arp_entry_t), ARP_CACHE_SIZE, NLOCKER_NONE);
    if (err < 0) {
        return err;
    }
    return NET_ERR_OK;
}

net_err_t arp_init() {
    net_err_t err = cache_init();
    if (err < 0) {
        dbg_error(DBG_ARP, "arp cache init failed.");
        return err;
    }

    return NET_ERR_OK;
}

net_err_t arp_make_request(netif_t *netif, const ipaddr_t *dest) {
    pktbuf_t *buf = pktbuf_alloc(sizeof(arp_pkt_t));
    if (buf == (pktbuf_t *)0) {
        dbg_error(DBG_ARP, "alloc pktbuf failed.");
        return NET_ERR_OK;
    }

    pktbuf_set_cont(buf, sizeof(arp_pkt_t));

    arp_pkt_t *arp_packet = (arp_pkt_t *)pktbuf_data(buf);
    //填充协议字段
    arp_packet->htype = x_htons(ARP_HW_ETHER);
    arp_packet->ptype = x_htons(NET_PROTOCOL_IPv4);
    arp_packet->hwlen = ETHER_HWA_SIZE;
    arp_packet->plen = IPV4_ADDR_SIZE;
    arp_packet->opcode = x_htons(ARP_REQUEST);
    plat_memcpy(arp_packet->sender_hwaddr, netif->hwaddr.addr, ETHER_HWA_SIZE);
    ipaddr_to_buf(&netif->ipaddr, arp_packet->sender_paddr);
    plat_memset(arp_packet->target_hwaddr, 0, ETHER_HWA_SIZE);
    ipaddr_to_buf(dest, arp_packet->target_paddr);

    //这里不能再用以太网的out接口发送数据了,因为已经在这个接口(ether_out)里面了
    net_err_t err = ether_raw_out(netif, NET_PROTOCOL_ARP, ether_broadcast_addr(), buf);
    if (err < 0) {
        pktbuf_free(buf);
    }

    return err;
}