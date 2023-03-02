#include "arp.h"
#include "dbg.h"
#include "mblock.h"
#include "tools.h"
#include "pktbuf.h"
#include "protocol.h"
#include "timer.h"

#define to_scan_cnt(tmo)    (tmo / ARP_TIMER_TMO)

static net_timer_t cache_timer;
static arp_entry_t cache_tbl[ARP_CACHE_SIZE];
static mblock_t cache_mblock;//用于对cache_tbl的分配
static nlist_t cache_list;//存放正在arp查询或者已经查询的arp
static const uint8_t empty_hwaddr[] = {0, 0, 0, 0, 0, 0};

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
    for (int i = 0; i < ARP_CACHE_SIZE; i++, entry++) {
        if ((entry->state != NET_ARP_WAITING) &&
            (entry->state != NET_ARP_RESOLVED)) {
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
#define display_arp_entry(entry)
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

static net_err_t cache_send_all(arp_entry_t *entry) {
    dbg_info(DBG_ARP, "send all packet");
    //dbg_dump_ip_buf(DBG_ARP, "ip:", entry->paddr);

    nlist_node_t *first;
    while((first = nlist_remove_first(&entry->buf_list))) {
        pktbuf_t *buf = nlist_entry(first, pktbuf_t, node);

        net_err_t err = ether_raw_out(entry->netif, NET_PROTOCOL_IPv4, entry->hwaddr, buf);
        if (err < 0) {
            pktbuf_free(buf);
        }
    }
    return NET_ERR_OK;
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
        nlist_node_init(&entry->node);
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

static arp_entry_t *cache_find(uint8_t *ip) {
    nlist_node_t *node;
    nlist_for_each(node, &cache_list) {
        arp_entry_t *entry = nlist_entry(node, arp_entry_t, node);
        if (plat_memcmp(ip, entry->paddr, IPV4_ADDR_SIZE) == 0) {
            //直接移到表头,再返回该项
            nlist_remove(&cache_list, &entry->node);
            nlist_insert_fist(&cache_list, &entry->node);
            return entry;
        }
    }

    return (arp_entry_t *)0;
}

static void cache_entry_set(arp_entry_t *entry, const uint8_t *hwaddr,
            uint8_t *ip, netif_t *netif, int state) {
    plat_memcpy(entry->hwaddr, hwaddr, ETHER_HWA_SIZE);
    plat_memcpy(entry->paddr, ip, IPV4_ADDR_SIZE);
    entry->state = state;
    entry->netif = netif;
    
    if (state == NET_ARP_RESOLVED) {
        entry->tmo = to_scan_cnt(ARP_ENTRY_STABLE_TMO);
    } else {
        entry->retry = to_scan_cnt(ARP_ENTRY_PENDING_TMO);
    }
}

static net_err_t cache_insert(netif_t *netif, uint8_t *ip, uint8_t *hwaddr, int force) {
    if (*(uint32_t *)ip == 0) {
        return NET_ERR_NOT_SUPPORT;
    }
    
    //查找是否已存在该表项
    arp_entry_t *entry = cache_find(ip);
    if (!entry) {
        entry = cache_alloc(force);
        if (!entry) {
            //dbg_dump_ip_buf(DBG_ARP, "alloc failed, ip:", ip);
            return NET_ERR_NONE;
        }

        cache_entry_set(entry, hwaddr, ip, netif, NET_ARP_RESOLVED);//这里不应是NET_ARP_WAIT?
        nlist_insert_fist(&cache_list, &entry->node);
    } else {
        //已有表项,则进行更新
        //dbg_dump_ip_buf(DBG_ARP, "update arp entry, ip:", ip);
        cache_entry_set(entry, hwaddr, ip, netif, NET_ARP_RESOLVED);

        //将表项移至开头(TODO:应该需要删掉,后面处理)
        if (nlist_first(&cache_list) != &entry->node) {
            nlist_remove(&cache_list, &entry->node);
            nlist_insert_fist(&cache_list, &entry->node);
        }

        //将存放的未发送的数据包全部发送出去
        net_err_t err = cache_send_all(entry);
        if (err < 0) {
            dbg_error(DBG_ARP, "send packet failed");
            return err;
        }
    }

    display_arp_tbl();
    return NET_ERR_OK;
}

const uint8_t *arp_find(netif_t *netif, ipaddr_t *ipaddr) {
    //判断是否是定向广播或者本地广播
    if (ipaddr_is_local_broadcast(ipaddr) 
        || ipaddr_is_direct_broadcast(ipaddr, &netif->netmask)) {
        return ether_broadcast_addr();
    }

    arp_entry_t *entry = cache_find(ipaddr->a_addr);
    if (entry && (entry->state == NET_ARP_RESOLVED)) {
        return entry->hwaddr;
    }

    return (const uint8_t *)0;
}

static void arp_cache_tmo(net_timer_t *timer, void *arg) {
    int changed_cnt = 0;//表项变化时打印

    nlist_node_t *curr, *next;
    for (curr = cache_list.first; curr; curr = next) {
        next = nlist_node_next(curr);

        arp_entry_t *entry = nlist_entry(curr, arp_entry_t, node);
        if (--entry->tmo > 0) {
            continue;
        }

        changed_cnt++;

        switch (entry->state)
        {
        case NET_ARP_RESOLVED:
            //重新进行请求
            dbg_info(DBG_ARP, "state to pending:");
            display_arp_entry(entry);

            ipaddr_t ipaddr;
            ipaddr_from_buf(&ipaddr, entry->paddr);

            entry->state = NET_ARP_WAITING;
            entry->tmo = to_scan_cnt(ARP_ENTRY_PENDING_TMO);//等待arp回应最多等多久
            //当已经发送arp,等待回包,但是回包可能丢包,所以需要尝试重新发送
            entry->retry = ARP_ENTRY_RETRY_CNT;
            arp_make_request(entry->netif, &ipaddr);
            break;
        case NET_ARP_WAITING:
            if (--entry->retry == 0) {
                //超过重试次数,则目标机器可能有问题,释放该表项
                dbg_info(DBG_ARP, "pending tmo, free it");
                display_arp_entry(entry);
                cache_free(entry);
            } else {
                //再次发送arp
                dbg_info(DBG_ARP, "penging tmo, send request");
                display_arp_entry(entry);

                ipaddr_t ipaddr;
                ipaddr_from_buf(&ipaddr, entry->paddr);
                entry->tmo = to_scan_cnt(ARP_ENTRY_PENDING_TMO);//等待arp回应最多等多久
                arp_make_request(entry->netif, &ipaddr);
            }
            break;
        default:
            dbg_error(DBG_ARP, "unknow arp state");
            display_arp_entry(entry);
            break;
        }
    }

    if (changed_cnt) {
        dbg_info(DBG_ARP, "%d arp entry changed.", changed_cnt);
        display_arp_tbl();
    }
}

net_err_t arp_init() {
    net_err_t err = cache_init();
    if (err < 0) {
        dbg_error(DBG_ARP, "arp cache init failed.");
        return err;
    }

    err = net_timer_add(&cache_timer, "arp timer", arp_cache_tmo, 
                        (void *)0, ARP_TIMER_TMO * 1000, NET_TIMER_RELOAD);
    if (err < 0) {
        dbg_error(DBG_ARP, "create timer failed: %d", err);
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

    arp_pkt_display(arp_packet);

    //只要是发给自己的包,则创建arp缓存或者更新arp缓存,这样后面如果要发送数据包给
    //目的主机就不需要发送arp了
    ipaddr_t target_ip;
    ipaddr_from_buf(&target_ip, arp_packet->target_paddr);
    if (ipaddr_is_equal(&netif->ipaddr, &target_ip)) {
        dbg_info(DBG_ARP, "receive an arp for me");

        cache_insert(netif, arp_packet->sender_paddr, arp_packet->sender_hwaddr, 1);

        //如果是arp请求包,对arp包做处理
        if (x_ntohs(arp_packet->opcode) == ARP_REQUEST) {
            dbg_info(DBG_ARP, "arp request, send reply");
            return arp_make_reply(netif, buf);
        }
    } else {
        //如果目标地址非本地ip的,则非强制性缓存,后面如果要发送数据,也可以不用发arp
        //比如其他计算机刚启动时发送的宣告
        cache_insert(netif, arp_packet->sender_paddr, arp_packet->sender_hwaddr, 0);
    }

    pktbuf_free(buf);
    return NET_ERR_OK;
}

void arp_clear(netif_t *netif) {
    nlist_node_t *node, *next;
    for (node = nlist_first(&cache_list); node; node = next) {
        next = nlist_node_next(node);

        arp_entry_t *e = nlist_entry(node, arp_entry_t, node);
        if (e->netif == netif) {
            nlist_remove(&cache_list, node);
        }
    }
}

net_err_t arp_resolve(netif_t *netif, const ipaddr_t *ipaddr, pktbuf_t *buf) {
    uint8_t ip_buf[IPV4_ADDR_SIZE];
    ipaddr_to_buf(ipaddr, ip_buf);

    arp_entry_t *entry = cache_find((uint8_t *)ip_buf);
    if (entry) {
        dbg_info(DBG_ARP, "found an arp entry");

        //已经解析好的情况
        if (entry->state == NET_ARP_RESOLVED) {
            return ether_raw_out(netif, NET_PROTOCOL_IPv4, entry->hwaddr, buf);
        }

        //还没有解析好的情况,并且挂载数量仍有空间
        if (nlist_count(&entry->buf_list) <= ARP_MAX_PKT_WAIT) {
            dbg_info(DBG_ARP, "insert buf to arp entry");
            nlist_insert_last(&entry->buf_list, &buf->node);
            return NET_ERR_OK;
        } else {
            dbg_warning(DBG_ARP, "too many waiting...");
            return NET_ERR_FULL;
        }
    } else {
        dbg_info(DBG_ARP, "make arp request");

        entry = cache_alloc(1);
        if (entry == (arp_entry_t *)0) {
            dbg_error(DBG_ARP, "alloc arp failed.");
            return NET_ERR_NONE;
        }

        cache_entry_set(entry, empty_hwaddr, (uint8_t *)ip_buf, netif, NET_ARP_WAITING);
        nlist_insert_fist(&cache_list, &entry->node);
        //挂载数据包
        nlist_insert_last(&entry->buf_list, &buf->node);

        display_arp_tbl();

        return arp_make_request(netif, ipaddr);
    }
}