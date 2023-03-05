#include "icmpv4.h"
#include "dbg.h"

net_err_t icmpv4_init(void) {
    dbg_info(DBG_ICMPv4, "init icmp");

    dbg_info(DBG_ICMPv4, "done");
    return NET_ERR_OK;
}
net_err_t icmpv4_in(ipaddr_t *src_ip, ipaddr_t *netif_in, pktbuf_t *buf) {
    return NET_ERR_OK;
}