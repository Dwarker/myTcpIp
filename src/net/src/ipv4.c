#include "ipv4.h"
#include "dbg.h"
#include "pktbuf.h"
#include "tools.h"
#include "protocol.h"
#include "icmpv4.h"
#include "mblock.h"

static uint16_t packet_id = 0;

static ip_frag_t frag_array[IP_FLAGS_MAX_NR];
static mblock_t frag_mblock;//存放空的分片链表
static nlist_t frag_list;//组织分片列表

static int get_data_size(ipv4_pkt_t *pkt) {
    return pkt->hdr.total_len - ipv4_hdr_size(pkt);//数据大小
}

static uint16_t get_frag_start(ipv4_pkt_t *pkt) {
    return pkt->hdr.frag_offset * 8;
}

static uint16_t get_frag_end(ipv4_pkt_t *pkt) {
    return get_frag_start(pkt) + get_data_size(pkt);
}

#if DBG_DISP_ENABLED(DBG_IP)
static void display_ip_frags(void) {
    plat_printf("ip frags:\n");

    int f_index = 0;
    nlist_node_t *f_node;
    nlist_for_each(f_node, &frag_list) {
        ip_frag_t *frag = nlist_entry(f_node, ip_frag_t, node);

        plat_printf("[%d]: \n", f_index++);
        dbg_dump_ip("   ip:", &frag->ip);
        plat_printf("   id: %d\n", frag->id);
        plat_printf("   tmo: %d\n", frag->tmo);
        plat_printf("   bufs: %d\n", nlist_count(&frag->buf_list));

        plat_printf("   bufs:\n");
        nlist_node_t *p_node;
        int p_index = 0;
        nlist_for_each(p_node, &frag->buf_list) {
            pktbuf_t *buf = nlist_entry(p_node, pktbuf_t, node);

            ipv4_pkt_t *pkt = (ipv4_pkt_t *)pktbuf_data(buf);
            plat_printf("   B%d:[%d-%d],  ", p_index++, get_frag_start(pkt), get_frag_end(pkt) - 1);
        }
        plat_printf("\n");
    }
}

static void display_ip_pkt(ipv4_pkt_t *pkt) {
    ipv4_hdr_t *ip_hdr = &(pkt->hdr);

    plat_printf("-------------ip------------\n");
    plat_printf("   version: %d\n", ip_hdr->version);
    plat_printf("   header len:  %d\n", ipv4_hdr_size(pkt));
    plat_printf("   total len: %d\n", ip_hdr->total_len);
    plat_printf("   id: %d\n", ip_hdr->id);
    plat_printf("   ttl: %d\n", ip_hdr->ttl);
    plat_printf("   frag offset: %d\n", ip_hdr->frag_offset);
    plat_printf("   frag more: %d\n", ip_hdr->more);
    plat_printf("   protocol: %d\n", ip_hdr->protocol);
    plat_printf("   checksum: %d\n", ip_hdr->hdr_checksum);
    dbg_dump_ip_buf("   src ip:", ip_hdr->src_ip);
    dbg_dump_ip_buf("   dest ip:", ip_hdr->dest_ip);
    plat_printf("\n-------------ip end-----------\n");
}
#else
#define display_ip_pkt(pkt)
#define display_ip_frags()
#endif

net_err_t frag_init(void) {
    nlist_init(&frag_list);
    mblock_init(&frag_mblock, frag_array, sizeof(ip_frag_t), IP_FLAGS_MAX_NR, NLOCKER_NONE);
    return NET_ERR_OK;
}

static void frag_free_buf_list(ip_frag_t *frag) {
    nlist_node_t *node;
    while ((node = nlist_remove_first(&frag->buf_list))) {
        pktbuf_t *buf = nlist_entry(node, pktbuf_t, node);
        pktbuf_free(buf);
    }
}

static ip_frag_t *frag_alloc(void) {
    ip_frag_t *frag = mblock_alloc(&frag_mblock, -1);
    if (!frag) {
        //将放的最久的分片头移除
        nlist_node_t *node = nlist_remove_last(&frag_list);
        frag = nlist_entry(node, ip_frag_t, node);
        if (frag) {
            //移除分片
            frag_free_buf_list(frag);
        }
    }

    //返回分片头
    return frag;
}

//释放分片头和分片
static void frag_free(ip_frag_t *frag) {
    frag_free_buf_list(frag);
    nlist_remove(&frag_list, &frag->node);
    mblock_free(&frag_mblock, frag);
}

static void frag_add(ip_frag_t *frag, ipaddr_t *ip, uint16_t id) {
    ipaddr_copy(&frag->ip, ip);
    frag->tmo = 0;
    frag->id = id;
    nlist_node_init(&frag->node);
    nlist_init(&frag->buf_list);

    //将该分片头放入链表管理器中
    nlist_insert_fist(&frag_list, &frag->node);
}

//查找分片头
static ip_frag_t *frag_find(ipaddr_t *ip, uint16_t id) {
    nlist_node_t *curr;

    nlist_for_each(curr, &frag_list) {
        ip_frag_t *frag = nlist_entry(curr, ip_frag_t, node);
        if (ipaddr_is_equal(ip, &frag->ip) && (id == frag->id)) {
            //将该分片头调整至链表头:因为后面的数据包很可能也需要链接入这个链表头,
            //这样减少查询时间
            nlist_remove(&frag_list, curr);
            nlist_insert_fist(&frag_list, curr);
            return frag;
        }
    }
    return (ip_frag_t *)0;
}

net_err_t ipv4_init(void) {
    dbg_info(DBG_IP, "init ip\n");

    net_err_t err = frag_init();
    if (err < 0) {
        dbg_error(DBG_IP, "frag init failed.");
        return err;
    }
    dbg_info(DBG_IP, "done");
    return NET_ERR_OK;
}

//检查包的合法性
static net_err_t is_pkt_ok(ipv4_pkt_t *pkt, int size, netif_t *netif) {
    if (pkt->hdr.version != NET_VERSION_IPV4) {
        dbg_warning(DBG_IP, "invalid ip version");
        return NET_ERR_NOT_SUPPORT;
    }

    int hdr_len = ipv4_hdr_size(pkt);
    if (hdr_len < sizeof(ipv4_hdr_t)) {
        dbg_warning(DBG_IP, "ipv4 header error");
        return NET_ERR_SIZE;
    }

    //对整个数据包的长度做检查(需要再看)
    int total_size = x_ntohs(pkt->hdr.total_len);
    if ((total_size < sizeof(ipv4_hdr_t)) || (size < total_size)) {
        dbg_warning(DBG_IP, "ipv4 size error");
        return NET_ERR_SIZE;
    }

    if (pkt->hdr.hdr_checksum) {
        uint16_t c = checksum16(pkt, hdr_len, 0, 1);
        if (c != 0) {
            dbg_warning(DBG_IP, "bad checksum");
            return NET_ERR_BROKEN;
        }
    }

    return NET_ERR_OK;
}

static void iphdr_ntohs(ipv4_pkt_t *pkt) {
    pkt->hdr.total_len = x_ntohs(pkt->hdr.total_len);
    pkt->hdr.id = x_ntohs(pkt->hdr.id);
    pkt->hdr.frag_all = x_ntohs(pkt->hdr.frag_all);
}

static void iphdr_htons(ipv4_pkt_t *pkt) {
    pkt->hdr.total_len = x_htons(pkt->hdr.total_len);
    pkt->hdr.id = x_htons(pkt->hdr.id);
    pkt->hdr.frag_all = x_htons(pkt->hdr.frag_all);
}

static net_err_t ip_frag_in(netif_t *netif, pktbuf_t *buf, ipaddr_t *src_ip, ipaddr_t *dest_ip) {
    ipv4_pkt_t *curr = (ipv4_pkt_t *)pktbuf_data(buf);

    //同一个数据包,hdr.id不变
    ip_frag_t *frag = frag_find(src_ip, curr->hdr.id);
    if (!frag) {
        frag = frag_alloc();
        frag_add(frag, src_ip, curr->hdr.id);
    }
    display_ip_frags();
    return NET_ERR_OK;
}

static net_err_t ip_normal_in(netif_t *netif, pktbuf_t *buf, ipaddr_t *src_ip, ipaddr_t *dest_ip) {
    ipv4_pkt_t *pkt = (ipv4_pkt_t *)pktbuf_data(buf);

    display_ip_pkt(pkt);

    switch (pkt->hdr.protocol)
    {
    case NET_PROTOCOL_ICMPv4: {
            //这里第二个参数不用dest_ip,是因为有可能是广播地址
            net_err_t err = icmpv4_in(src_ip, &netif->ipaddr, buf);
            if (err < 0) {
                dbg_warning(DBG_IP, "icmp in failed.");
                return err;
            }
            break;
        }
    case NET_PROTOCOL_UDP:
        //不管发过来的是什么udp数据,暂时都回端口不可达
        iphdr_htons(pkt);
        icmpv4_out_unreach(src_ip, &netif->ipaddr, ICMPv4_UNREACH_PORT, buf);
        break;
    case NET_PROTOCOL_TCP:
        break;
    default:
        dbg_warning(DBG_IP, "unknow protocol");
        break;
    }

    return NET_ERR_UNREACH;
}

net_err_t ipv4_in(netif_t *netif, pktbuf_t *buf) {
    dbg_info(DBG_IP, "ip in\n");

    net_err_t err = pktbuf_set_cont(buf, sizeof(ipv4_hdr_t));
    if (err < 0) {
        dbg_error(DBG_IP, "ajust header failed, err = %d\n", err);
        return err;
    }

    ipv4_pkt_t *pkt = (ipv4_pkt_t *)pktbuf_data(buf);
    if (is_pkt_ok(pkt, buf->total_size, netif) != NET_ERR_OK) {
        dbg_warning(DBG_IP, "packet is broken.");
        return err;
    }

    //调整数据包大小,因为如果小于46个字节,后面会填充0,
    //所以要调整为真实数据的大小,协议头里面的total_len字段就是真实数据大小
    iphdr_ntohs(pkt);
    err = pktbuf_resize(buf, pkt->hdr.total_len);
    if (err < 0) {
        dbg_error(DBG_IP, "ip pkt resize failed.");
        return err;
    }

    //判断是否发给自己
    ipaddr_t dest_ip, src_ip;
    ipaddr_from_buf(&dest_ip, pkt->hdr.dest_ip);
    ipaddr_from_buf(&src_ip, pkt->hdr.src_ip);

    if (!ipaddr_is_match(&dest_ip, &netif->ipaddr, &netif->netmask)) {
        //上层释放
        dbg_error(DBG_IP, "ipaddr not match");
        return NET_ERR_UNREACH;
    }

    //处理存在分片的情况
    if (pkt->hdr.frag_offset || pkt->hdr.more) {
        err = ip_frag_in(netif, buf, &src_ip, &dest_ip);
    } else {
        //不分片的情况
        err = ip_normal_in(netif, buf, &src_ip, &dest_ip);
    }

    //pktbuf_free(buf);
    return NET_ERR_OK;
}

net_err_t ipv4_out(uint8_t protocol, ipaddr_t *dest, ipaddr_t *src, pktbuf_t *buf) {
    dbg_info(DBG_IP, "send an ip pkt");

    net_err_t err = pktbuf_add_header(buf, sizeof(ipv4_hdr_t), 1);
    if (err < 0) {
        dbg_error(DBG_IP, "add header failed");
        return NET_ERR_SIZE;
    }

    ipv4_pkt_t *pkt = (ipv4_pkt_t *)pktbuf_data(buf);
    pkt->hdr.shdr_all = 0;//暂时设置为0
    pkt->hdr.version = NET_VERSION_IPV4;
    ipv4_set_hdr_size(pkt, sizeof(ipv4_hdr_t));
    pkt->hdr.total_len = buf->total_size;
    pkt->hdr.id = packet_id++;
    pkt->hdr.frag_all = 0;
    pkt->hdr.ttl = NET_IP_DEFAULT_TTL;
    pkt->hdr.protocol = protocol;
    pkt->hdr.hdr_checksum = 0;
    ipaddr_to_buf(src, pkt->hdr.src_ip);
    ipaddr_to_buf(dest, pkt->hdr.dest_ip);

    iphdr_htons(pkt);
    pktbuf_reset_acc(buf);//重置所有游标
    pkt->hdr.hdr_checksum = pktbuf_checksum16(buf, ipv4_hdr_size(pkt), 0, 1);

    display_ip_pkt(pkt);
    
    err = netif_out(netif_get_default(), dest, buf);
    if (err < 0) {
        dbg_warning(DBG_IP, "send ip packet");
        return err;
    }

    return NET_ERR_OK;
}