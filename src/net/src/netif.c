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

netif_t *netif_open(const char *dev_name, const netif_ops_t *ops, void *ops_data) {
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
        mblock_free(&netif_mblock, netif);
        return (netif_t *)0;
    }

    err = fixq_init(&netif->out_q, netif->out_q_buf, NETIF_OUTQ_SIZE, NLOCKER_THREAD);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif out_q init failed.");
        mblock_free(&netif_mblock, netif);
        fixq_destroy(&netif->in_q);
        return (netif_t *)0;
    }

    //对网卡本身进行打开
    err = ops->open(netif, ops_data);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif ops open err.");
        goto free_return;
    }
    netif->ops = ops;
    netif->ops_data = ops_data;
    netif->state = NETIF_OPENED;

    //网卡驱动打开网卡存在问题
    if (netif->type == NETIF_TYPE_NONE) {
        dbg_error(DBG_NETIF, "netif type unknow.");
        goto free_return;
    }

    nlist_insert_last(&netif_list, &netif->node);

    return netif;
free_return:
    if (netif->state == NETIF_OPENED) {
        netif->ops->close(netif);
    }
    fixq_destroy(&netif->in_q);
    fixq_destroy(&netif->out_q);
    mblock_free(&netif_mblock, netif);
    return (netif_t *)0;
}