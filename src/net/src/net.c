#include "net.h"
#include "exmsg.h"
#include "net_plat.h"
#include "pktbuf.h"
#include "dbg.h"
#include "netif.h"
#include "loop.h"
#include "ether.h"
#include "tools.h"
#include "timer.h"
#include "net.h"
#include "ipv4.h"
#include "icmpv4.h"
#include "sock.h"
#include "raw.h"
#include "udp.h"
#include "tcp.h"

net_err_t net_init(void) {
    dbg_info(DBG_INIT, "init net");

    net_plat_init();//平台相关

    tools_init();
    
    exmsg_init();
    pktbuf_init();
    netif_init();
    net_timer_init();
    
    ether_init();

    arp_init();//会用到定时器,所以放在定时器模块初始化之后
    ipv4_init();
    icmpv4_init();

    socket_init();
    raw_init();
    udp_init();
    tcp_init();

    loop_init();

    return NET_ERR_OK;
}
net_err_t net_start(void) {
    exmsg_start();
    dbg_info(DBG_INIT, "net is running");
    return NET_ERR_OK;
}