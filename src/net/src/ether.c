#include "ether.h"
#include "netif.h"
#include "dbg.h"
#include "tools.h"
#include "protocol.h"
#include "arp.h"
#include "ipv4.h"

#if DBG_DISP_ENABLED(DBG_ETHER)
//输出以太网包相关信息
static void display_ether_pkt(char *title, ether_pkt_t *pkt, int total_size) {
    ether_hdr_t *hdr = &pkt->hdr;

    plat_printf("----------- %s -----------\n", title);
    plat_printf("\t len: %d bytes\n", total_size);
    dbg_dump_hwaddr("\t dest:", hdr->dest, ETHER_HWA_SIZE);
    dbg_dump_hwaddr("\t src:", hdr->src, ETHER_HWA_SIZE);
    plat_printf("\ttype: %04x\n", x_ntohs(hdr->protocol));

    switch (x_ntohs(hdr->protocol))
    {
    case NET_PROTOCOL_ARP :
        plat_printf("arp\n");
        break;
    case NET_PROTOCOL_IPv4 :
        plat_printf("IPv4\n");
        break;
    default:
        plat_printf("unknow\n");
        break;
    }
    plat_printf("\n");
}
#else
#define display_ether_pkt(title, pkt, size)
#endif

static net_err_t ether_open (struct _netif_t *netif) {

    //发送无回报arp报文,目标IP地址填入的是本地IP
    return arp_make_gratuitous(netif);
}

static void ether_close (struct _netif_t *netif) {

}

static net_err_t is_pkt_ok(ether_pkt_t *frame, int total_size) {
    if (total_size > (sizeof(ether_hdr_t) + ETHER_MTU)) {
        dbg_warning(DBG_ETHER, "frame size too big: %d", total_size);
        return NET_ERR_SIZE;
    }
    if (total_size < sizeof(ether_hdr_t)) {
        dbg_warning(DBG_ETHER, "frame size too small: %d", total_size);
        return NET_ERR_SIZE;
    }
    return NET_ERR_OK;
}

static net_err_t ether_in (struct _netif_t *netif, pktbuf_t *buf) {
    dbg_info(DBG_ETHER, "ether in");

    //包头可能不在一个数据块中,故合并成一个数据块
    pktbuf_set_cont(buf, sizeof(ether_hdr_t));
    ether_pkt_t *pkt = (ether_pkt_t *)pktbuf_data(buf);

    net_err_t err = is_pkt_ok(pkt, buf->total_size);
    if (err < 0) {
        dbg_warning(DBG_ETHER, "ether pkt error.");
        return err;
    }

    display_ether_pkt("ether in", pkt, buf->total_size);

    switch (x_ntohs(pkt->hdr.protocol))
    {
        case NET_PROTOCOL_ARP: {
            //将接收到的arp包,移除以太网包头
            err = pktbuf_remove_header(buf, sizeof(ether_hdr_t));
            if (err < 0) {
                dbg_error(DBG_ETHER, "remove header failed.");
                return NET_ERR_SIZE;
            }
            //传给arp模块
            return arp_in(netif, buf);
        }
        case NET_PROTOCOL_IPv4: {
            //移除以太网头
            err = pktbuf_remove_header(buf, sizeof(ether_hdr_t));
            if (err < 0) {
                dbg_error(DBG_ETHER, "remove header failed.");
                return NET_ERR_SIZE;
            }

            return ipv4_in(netif, buf);
        }
        default:
            break;
    }

    pktbuf_free(buf);
    return NET_ERR_OK;
}

static net_err_t ether_out (struct _netif_t *netif, ipaddr_t *dest, pktbuf_t *buf) {
    if (ipaddr_is_equal(&netif->ipaddr, dest)) {
        //这里不用判断也可以,ether_raw_out中会有判断
        return ether_raw_out(netif, NET_PROTOCOL_IPv4, (const uint8_t *)netif->hwaddr.addr, buf);
    }

    const uint8_t *hwaddr = arp_find(netif, dest);
    if (hwaddr) {
        return ether_raw_out(netif, NET_PROTOCOL_IPv4, hwaddr, buf);
    } else {
        //若是没有mac地址,则将buf挂载上去,利用arp协议去查询,查询完毕后再发送
        return arp_resolve(netif, dest, buf);
    }
}

net_err_t ether_init(void) {
    static const link_layer_t link_layer = {
        .type = NETIF_TYPE_ETHER,
        .open = ether_open,
        .close = ether_close,
        .in = ether_in,
        .out = ether_out
    };

    dbg_info(DBG_NETIF, "init ether\n");

    net_err_t err = netif_register_layer(NETIF_TYPE_ETHER, &link_layer);
    if (err < 0) {
        dbg_info(DBG_ETHER, "register error");
        return err;
    }

    dbg_info(DBG_ETHER, "init ether done\n");
    return NET_ERR_OK;
}

const uint8_t *ether_broadcast_addr(void) {
    //广播地址
    static const uint8_t broadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return broadcast;
}

//发送数据包 dest为目标网卡硬件地址
net_err_t ether_raw_out(netif_t *netif, uint16_t protocol, const uint8_t *dest, pktbuf_t *buf) {
    net_err_t err;
    
    int size = pktbuf_total(buf);
    if (size < ETHER_DATA_MIN) {
        dbg_info(DBG_ETHER, "resize from %d to %d", size, ETHER_DATA_MIN);

        //当数据不足46字节时,需要扩充成46字节,并填充0
        err = pktbuf_resize(buf, ETHER_DATA_MIN);
        if (err < 0) {
            dbg_error(DBG_ETHER, "resize error");
            return err;
        }

        pktbuf_reset_acc(buf);
        pktbuf_seek(buf, size);
        pktbuf_fill(buf, 0, ETHER_DATA_MIN - size);

        size = ETHER_DATA_MIN;
    }

    //填充以太网协议包头:目标地址,源地址,协议类型
    err = pktbuf_add_header(buf, sizeof(ether_hdr_t), 1);
    if (err < 0) {
        dbg_error(DBG_ETHER, "add header error: %d", err);
        return NET_ERR_SIZE;
    }

    ether_pkt_t *pkt = (ether_pkt_t*)pktbuf_data(buf);
    plat_memcpy(pkt->hdr.dest, dest, ETHER_HWA_SIZE);
    plat_memcpy(pkt->hdr.src, netif->hwaddr.addr, ETHER_HWA_SIZE);
    pkt->hdr.protocol = x_htons(protocol);

    display_ether_pkt("ether out", pkt, size);

    //如果是A网卡发给A网卡的,直接仍到A网卡的输入队列
    if (plat_memcmp(netif->hwaddr.addr, dest, ETHER_HWA_SIZE) == 0) {
        return netif_put_in(netif, buf, -1);
    } else {
        //送入发送队列
        err = netif_put_out(netif, buf, -1);
        if (err < 0) {
            dbg_warning(DBG_ETHER, "put pkt out failed.");
            return err;
        }

        //调用对应协议的驱动接口,从发送队列取出后,进行发送
        return netif->ops->xmit(netif);
    }
}