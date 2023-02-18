#include "netif.h"
#include "mblock.h"
#include "dbg.h"

static netif_t netif_buffer[NETIF_DEV_CNT];
static mblock_t netif_mblock;
static nlist_t netif_list;//用来组织打开的网络接口
static netif_t *netif_default;//默认使用该网卡进行发送

net_err_t netif_init (void) {
    dbg_info(DBG_NETIF, "init netif\n");

    nlist_init(&netif_list);
    mblock_init(&netif_mblock, netif_buffer, sizeof(netif_t), 
                    NETIF_DEV_CNT, NLOCKER_NONE);
    
    netif_default = (netif_t *)0;

    dbg_info(DBG_NETIF, "init done\n");
    return NET_ERR_OK;
}