#include "ipv4.h"
#include "dbg.h"
#include "pktbuf.h"
#include "tools.h"
#include "protocol.h"
#include "icmpv4.h"

static uint16_t packet_id = 0;

#if DBG_DISP_ENABLED(DBG_IP)
static void display_ip_pkt(ipv4_pkt_t *pkt) {
    ipv4_hdr_t *ip_hdr = &(pkt->hdr);

    plat_printf("-------------ip------------\n");
    plat_printf("   version: %d\n", ip_hdr->version);
    plat_printf("   header len:  %d\n", ipv4_hdr_size(pkt));
    plat_printf("   total len: %d\n", ip_hdr->total_len);
    plat_printf("   id: %d\n", ip_hdr->id);
    plat_printf("   ttl: %d\n", ip_hdr->ttl);
    plat_printf("   protocol: %d\n", ip_hdr->protocol);
    plat_printf("   checksum: %d\n", ip_hdr->hdr_checksum);
    dbg_dump_ip_buf("   src ip:", ip_hdr->src_ip);
    dbg_dump_ip_buf("   dest ip:", ip_hdr->dest_ip);
    plat_printf("\n-------------ip end-----------\n");
}
#else
#define display_ip_pkt(pkt)
#endif

net_err_t ipv4_init(void) {
    dbg_info(DBG_IP, "init ip\n");

    dbg_info(DBG_IP, "done");
    return NET_ERR_OK;
}

//检查包的合法性
static net_err_t is_pkt_pk(ipv4_pkt_t *pkt, int size, netif_t *netif) {
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
        break;
    case NET_PROTOCOL_TCP:
        break;
    default:
        dbg_warning(DBG_IP, "unknow protocol");
        break;
    }

    return NET_ERR_OK;
}

net_err_t ipv4_in(netif_t *netif, pktbuf_t *buf) {
    dbg_info(DBG_IP, "ip in\n");

    net_err_t err = pktbuf_set_cont(buf, sizeof(ipv4_hdr_t));
    if (err < 0) {
        dbg_error(DBG_IP, "ajust header failed, err = %d\n", err);
        return err;
    }

    ipv4_pkt_t *pkt = (ipv4_pkt_t *)pktbuf_data(buf);
    if (is_pkt_pk(pkt, buf->total_size, netif) != NET_ERR_OK) {
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

    //不分片的情况
    err = ip_normal_in(netif, buf, &src_ip, &dest_ip);

    pktbuf_free(buf);
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