#include "arp.h"
#include "dbg.h"
#include "mblock.h"
#include "tools.h"
#include "pktbuf.h"
#include "protocol.h"

static arp_entry_t cache_tbl[ARP_CACHE_SIZE];
static mblock_t cache_mblock;//用于对cache_tbl的分配
static nlist_t cache_list;//存放正在arp查询或者已经查询的arp

#if DBG_DISP_ENABLED(DBG_ARP)

static void display_arp_entry(arp_entry_t *entry) {
    plat_printf("%d: ", (int)(entry - cache_tbl));
    dbg_dump_ip_buf("  ip: ", entry->paddr);
    dbg_dump_hwaddr("  mac:", entry->hwaddr, ETHER_HWA_SIZE);

    plat_printf("tmo: %d, retry: %d, %s, buf: %d\n",
                entry->tmo, entry->retry, entry->state == NET_ARP_RESOLVED ? "stable" : "pending",
                nlist_count(&entry->buf_list));
}

//打印已经解析好的arp表数据
static void display_arp_tbl(void) {
    plat_printf("-------- arp table start ----------\n");

    //cache_tbl这个里面的顺序是不变的,所以方便观察
    //cache_list这个头部可能会插入新的节点
    arp_entry_t *entry = cache_tbl;
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (entry->state != NET_ARP_FREE) {
            continue;
        }
        display_arp_entry(entry);
    }

    plat_printf("-------- arp table end ----------\n");
}

static void arp_pkt_display(arp_pkt_t *packet) {
    uint16_t opcode = x_ntohs(packet->opcode);

    plat_printf("----------- arp packet -------------\n");
    plat_printf("   htype: %d\n", x_ntohs(packet->htype));
    plat_printf("   ptype: %04x\n", x_ntohs(packet->ptype));
    plat_printf("   hlen: %d\n", packet->hwlen);
    plat_printf("   plen: %d\n", packet->plen);
    plat_printf("   type: %d\n", opcode);

    switch (opcode)
    {
    case ARP_REQUEST:
        plat_printf("request\n");
        break;
    case ARP_REPLY:
        plat_printf("reply\n");
        break;
    default:
        plat_printf("unknow\n");
        break;
    }

    dbg_dump_ip_buf("     sender:", packet->sender_paddr);
    dbg_dump_hwaddr("     mac:", packet->sender_hwaddr, ETHER_HWA_SIZE);
    dbg_dump_ip_buf("\n     target:", packet->target_paddr);
    dbg_dump_hwaddr("     mac:", packet->sender_hwaddr, ETHER_HWA_SIZE);
    plat_printf("\n----------arp end-----------\n");
}
#else
#define arp_pkt_display(packet)
#define display_arp_tbl()
#endif

//arp缓存表的初始化
static net_err_t cache_init(void) {
    nlist_init(&cache_list);
    net_err_t err = mblock_init(&cache_mblock, cache_tbl, sizeof(arp_entry_t), ARP_CACHE_SIZE, NLOCKER_NONE);
    if (err < 0) {
        return err;
    }
    return NET_ERR_OK;
}

static void cache_clear_all(arp_entry_t *entry) {
    dbg_info(DBG_ARP, "clear packet");

    nlist_node_t *first;
    while((first = nlist_remove_first(&entry->buf_list))) {
        pktbuf_t *buf = nlist_entry(first, pktbuf_t, node);
        pktbuf_free(buf);
    }
}

//arp缓存的分配:如果是强制分配,则把最久的那个节点释放掉(可能有未发送的数据,也释放)
static arp_entry_t *cache_alloc(int force) {
    arp_entry_t *entry = mblock_alloc(&cache_mblock, -1);
    if (!entry && force) {
        nlist_node_t *node = nlist_remove_last(&cache_list);
        if (!node) {
            dbg_warning(DBG_ARP, "alloc arp entry failed.");
            return (arp_entry_t *)0;
        }

        entry = nlist_entry(node, arp_entry_t, node);
        //清空未发送的数据包
        cache_clear_all(entry);
    }

    if (entry) {
        plat_memset(entry, 0, sizeof(arp_entry_t));
        entry->state = NET_ARP_FREE;
        nlist_node_init(&entry)
        nlist_init(&entry->buf_list);//存储未发送的数据包
    }

    return entry;
}

//释放某一表项
static void cache_free(arp_entry_t *entry) {
    cache_clear_all(entry);
    nlist_remove(&cache_list, &entry->node);
    mblock_free(&cache_mblock, entry);
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

    arp_pkt_display(arp_packet);

    //这里不能再用以太网的out接口发送数据了,因为已经在这个接口(ether_out)里面了
    net_err_t err = ether_raw_out(netif, NET_PROTOCOL_ARP, ether_broadcast_addr(), buf);
    if (err < 0) {
        pktbuf_free(buf);
    }

    return err;
}

net_err_t arp_make_gratuitous(netif_t *netif) {
    dbg_info(DBG_ARP, "send an gratuitous arp...");
    return arp_make_request(netif, &netif->ipaddr);
}

static net_err_t is_pkt_ok(arp_pkt_t *arp_packet, uint16_t size, netif_t *netif) {
    if (size < sizeof(arp_pkt_t)) {
        dbg_warning(DBG_ARP, "packet size error");
        return NET_ERR_SIZE;
    }

    if ((x_ntohs(arp_packet->htype) != ARP_HW_ETHER)
        || arp_packet->hwlen != ETHER_HWA_SIZE
        || (x_htons(arp_packet->ptype) != NET_PROTOCOL_IPv4)
        || (arp_packet->plen != IPV4_ADDR_SIZE)) {
            dbg_warning(DBG_ARP, "packet incorrect");
            return NET_ERR_NOT_SUPPORT;
    }

    uint16_t opcode = x_htons(arp_packet->opcode);
    if ((opcode != ARP_REPLY) && (opcode != ARP_REQUEST)) {
        dbg_warning(DBG_ARP, "unknow opcode");
        return NET_ERR_NOT_SUPPORT;
    }

    return NET_ERR_OK;
}

net_err_t arp_make_reply(netif_t *netif, pktbuf_t *buf) {
    arp_pkt_t *arp_packet = (arp_pkt_t *)pktbuf_data(buf);

    arp_packet->opcode = x_htons(ARP_REPLY);
    plat_memcpy(arp_packet->target_hwaddr, arp_packet->sender_hwaddr, ETHER_HWA_SIZE);
    plat_memcpy(arp_packet->target_paddr, arp_packet->sender_paddr, IPV4_ADDR_SIZE);
    plat_memcpy(arp_packet->sender_hwaddr, netif->hwaddr.addr, ETHER_HWA_SIZE);
    ipaddr_to_buf(&netif->ipaddr, arp_packet->sender_paddr);

    arp_pkt_display(arp_packet);

    return ether_raw_out(netif, NET_PROTOCOL_ARP, arp_packet->target_hwaddr, buf);
}

net_err_t arp_in(netif_t *netif, pktbuf_t *buf) {
    dbg_info(DBG_ARP, "arp in");

    net_err_t err = pktbuf_set_cont(buf, sizeof(arp_pkt_t));
    if (err < 0) {
        return err;
    }

    arp_pkt_t *arp_packet = (arp_pkt_t *)pktbuf_data(buf);
    if (is_pkt_ok(arp_packet, buf->total_size, netif) != NET_ERR_OK) {
        return err;
    }

    //对arp包做处理
    if (x_ntohs(arp_packet->opcode) == ARP_REQUEST) {
        dbg_info(DBG_ARP, "arp request, send reply");
        return arp_make_reply(netif, buf);
    }

    //暂时先直接释放
    pktbuf_free(buf);
    return NET_ERR_OK;
}