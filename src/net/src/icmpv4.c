#include "icmpv4.h"
#include "dbg.h"
#include "ipv4.h"
#include "protocol.h"

#if DBG_DISP_ENABLED(DBG_ICMPv4)
static void display_icmp_packet(char *title, icmpv4_pkt_t *pkt) {
    plat_printf("-----------%s----------\n", title);
    plat_printf("   type: %d\n", pkt->hdr.type);
    plat_printf("   code: %d\n", pkt->hdr.code);
    plat_printf("   checksum: %d\n", pkt->hdr.checksum);
    plat_printf("-----------------------\n");
}
#else
#define display_icmp_packet(title, pkt)
#endif

net_err_t icmpv4_init(void) {
    dbg_info(DBG_ICMPv4, "init icmp");

    dbg_info(DBG_ICMPv4, "done");
    return NET_ERR_OK;
}

static net_err_t icmpv4_out(ipaddr_t *dest, ipaddr_t *src, pktbuf_t *buf) {
    icmpv4_pkt_t *pkt = (icmpv4_pkt_t *)pktbuf_data(buf);

    pktbuf_reset_acc(buf);
    pkt->hdr.checksum = pktbuf_checksum16(buf, buf->total_size, 0, 1);

    display_icmp_packet("icmp out", pkt);
    return ipv4_out(NET_PROTOCOL_ICMPv4, dest, src, buf);
}

static net_err_t icmpv4_echo_reply(ipaddr_t *dest, ipaddr_t *src, pktbuf_t *buf) {
    icmpv4_pkt_t *pkt = (icmpv4_pkt_t *)pktbuf_data(buf);

    pkt->hdr.type = ICMPv4_ECHO_REPLY;
    pkt->hdr.checksum = 0;//发送的时候计算
    return icmpv4_out(dest, src, buf);
}

static net_err_t is_pkt_ok(icmpv4_pkt_t *pkt, int size, pktbuf_t *buf) {
    if (size <= sizeof(ipv4_hdr_t)) {
        dbg_warning(DBG_ICMPv4, "size error");
        return NET_ERR_SIZE;
    }

    uint16_t checksum = pktbuf_checksum16(buf, size, 0, 1);
    if (checksum != 0) {
        dbg_warning(DBG_ICMPv4, "bad checksum");
        return NET_ERR_BROKEN;
    }

    return NET_ERR_OK;
}

net_err_t icmpv4_in(ipaddr_t *src_ip, ipaddr_t *netif_in, pktbuf_t *buf) {
    dbg_info(DBG_ICMPv4, "icmpv4 in");

    ipv4_pkt_t *ip_pkt = (ipv4_pkt_t *)pktbuf_data(buf);
    int iphdr_size = ipv4_hdr_size(ip_pkt);

    net_err_t err = pktbuf_set_cont(buf, iphdr_size + sizeof(icmpv4_hdr_t));
    if (err < 0) {
        dbg_error(DBG_ICMPv4, "set icmp cont failed.");
        return err;
    }

    //因为合并操作,包头数据位置可能改变,所以重新获取下包头
    ip_pkt = (ipv4_pkt_t *)pktbuf_data(buf);

    //移除ip包头
    err = pktbuf_remove_header(buf, iphdr_size);
    if (err < 0) {
        dbg_error(DBG_ICMPv4, "remove ip header failed.");
        return NET_ERR_SIZE;
    }

    //重新设置游标,后面要检查校验和
    pktbuf_reset_acc(buf);

    //检查icmp包头
    icmpv4_pkt_t *icmp_pkt = (icmpv4_pkt_t *)pktbuf_data(buf);
    if ((err = is_pkt_ok(icmp_pkt, buf->total_size, buf)) < 0) {
        dbg_warning(DBG_ICMPv4, "icmp pkt error.");
        return err;
    }

    display_icmp_packet("icmp in", icmp_pkt);

    switch (icmp_pkt->hdr.type)
    {
    case ICMPv4_ECHO_REQUEST:
        return icmpv4_echo_reply(src_ip, netif_in, buf);
    default:
        pktbuf_free(buf);
        return NET_ERR_OK;
    }

    return NET_ERR_OK;
}