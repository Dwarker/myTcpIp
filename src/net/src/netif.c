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
    //这里因为是空闲的,所以可以不用管netif_buffer这个数据的结构体的成员分布,
    //链接起来就可以了,拿出来使用的时候才需要关注成员的布局
    mblock_init(&netif_mblock, netif_buffer, sizeof(netif_t), 
                    NETIF_DEV_CNT, NLOCKER_NONE);
    
    netif_default = (netif_t *)0;

    dbg_info(DBG_NETIF, "init done\n");
    return NET_ERR_OK;
}

netif_t *netif_open(const char *dev_name) {
    netif_t *netif = (netif_t *)mblock_alloc(&netif_mblock, -1);
    if (!netif) {
        dbg_error(DBG_NETIF, "no netif");
        return (netif_t *)0;
    }

    ipaddr_set_any(&netif->ipaddr);
    ipaddr_set_any(&netif->netmask);
    ipaddr_set_any(&netif->gateway);

    plat_strncpy(netif->name, dev_name, NETIF_NAME_SIZE);
    netif->name[NETIF_NAME_SIZE - 1] = '\0';
    
    //打开网卡的时候,不知道网卡类型,所以初始为0
    plat_memset(&netif->hwaddr, 0, sizeof(netif_haddr_t));
    netif->type = NETIF_TYPE_NONE;
    netif->mtu = 0;
    nlist_node_init(&netif->node);

    net_err_t err = fixq_init(&netif->in_q, netif->in_q_buf, NETIF_INQ_SIZE, NLOCKER_THREAD);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif in_q init failed.");
        return (netif_t *)0;
    }

    err = fixq_init(&netif->out_q, netif->out_q_buf, NETIF_OUTQ_SIZE, NLOCKER_THREAD);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif out_q init failed.");
        fixq_destroy(&netif->in_q);
        return (netif_t *)0;
    }

    netif->state = NETIF_OPENED;
    nlist_insert_last(&netif_list, &netif->node);

    return netif;
}