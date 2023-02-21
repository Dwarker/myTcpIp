#include "netif_pcap.h"
#include "sys_plat.h"
#include "net_err.h"
#include "exmsg.h"
#include "pcap.h"
#include "dbg.h"

//网卡数据接收线程
void recv_thread (void *arg) {
    plat_printf("recv thread is running...\n");

    netif_t *netif = (netif_t *)arg;
    pcap_t *pcap = (pcap_t *)netif->ops_data;

    while (1) {
        struct pcap_pkthdr *pkthdr;
        const uint8_t *pkt_data;
        //当无数据包时,会卡在这里
        if (pcap_next_ex(pcap, &pkthdr, &pkt_data) != 1) {
            continue;
        }

        pktbuf_t *buf = pktbuf_alloc(pkthdr->len);
        if (buf == (pktbuf_t *)0) {
            dbg_warning(DBG_NETIF, "buf == NULL");
            continue;
        }

        pktbuf_write(buf, (uint8_t *)pkt_data, pkthdr->len);

        //写入输入队列
        //这里使用线程做的,可以等待
        if (netif_put_in(netif, buf, 0) < 0) {
            dbg_warning(DBG_NETIF, "netif %s in_q full\n", netif->name);
            //如果塞入队列失败,那么释放
            pktbuf_free(buf);
            continue;
        }
    }
    
}

//网卡数据发送线程
void xmit_thread (void *arg) {
    plat_printf("xmit thread is running...\n");

    while (1) {
        sys_sleep(1);
    }
    
}

static net_err_t netif_pcap_open (struct _netif_t *netif, void *data) {
    pcap_data_t *dev_data = (pcap_data_t *)data;

    pcap_t *pcap = pcap_device_open(dev_data->ip, dev_data->hwaddr);
    if (pcap == (pcap_t *)0) {
        dbg_error(DBG_NETIF, "pcap open failed! name: %s\n", netif->name);
        return NET_ERR_IO;
    }

    netif->type = NETIF_TYPE_ETHER;
    netif->mtu = 1500;
    netif->ops_data = pcap;
    netif_set_hwaddr(netif, dev_data->hwaddr, 6);

    sys_thread_create(recv_thread, netif);
    sys_thread_create(xmit_thread, netif);
    return NET_ERR_OK;
}

static void netif_pcap_close (netif_t *netif) {
    pcap_t *pcap = (pcap_t *)netif->ops_data;
    pcap_close(pcap);
}

static net_err_t netif_pcap_xmit (netif_t *netif) {

    return NET_ERR_OK;
}

const netif_ops_t netdev_ops = {
    .open = netif_pcap_open,
    .close = netif_pcap_close,
    .xmit = netif_pcap_xmit,
};