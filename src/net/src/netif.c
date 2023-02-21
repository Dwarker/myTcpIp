#include "netif.h"
#include "mblock.h"
#include "dbg.h"
#include "pktbuf.h"
#include "exmsg.h"

static netif_t netif_buffer[NETIF_DEV_CNT];
static mblock_t netif_mblock;
static nlist_t netif_list;//用来组织打开的网络接口
static netif_t *netif_default;//默认使用该网卡进行发送

static const link_layer_t *link_layers[NETIF_TYPE_SIZE];

#if DBG_DISP_ENABLED(DBG_NETIF)
void display_netif_list (void) {
    plat_printf("netif list:\n");

    nlist_node_t *node;
    nlist_for_each(node, &netif_list) {
        netif_t *netif = nlist_entry(node, netif_t, node);

        plat_printf("%s:", netif->name);
        switch (netif->state)
        {
        case NETIF_CLOSED:
            plat_printf("  %s  ", "closed");
            break;
        case NETIF_OPENED:
            plat_printf("  %s  ", "opened");
            break;
        case NETIF_ACTIVE:
            plat_printf("  %s  ", "active");
            break;
        default:
            break;
        }

        switch (netif->type)
        {
        case NETIF_TYPE_ETHER:
            plat_printf("  %s  ", "ether");
            break;
        case NETIF_TYPE_LOOP:
            plat_printf("  %s  ", "loop");
            break;
        default:
            break;
        }

        plat_printf(" mtu=%d \n", netif->mtu);
        dbg_dump_hwaddr("hwaddr:", netif->hwaddr.addr, netif->hwaddr.len);
        dbg_dump_ip(" ip:", &netif->ipaddr);
        dbg_dump_ip(" netmask:", &netif->netmask);
        dbg_dump_ip(" gateway:", &netif->gateway);

        plat_printf("\n");
    }
}
#else
#define display_netif_list()
#endif

net_err_t netif_init (void) {
    dbg_info(DBG_NETIF, "init netif\n");

    nlist_init(&netif_list);
    //这里因为是空闲的,所以可以不用管netif_buffer这个数据的结构体的成员分布,
    //链接起来就可以了,拿出来使用的时候才需要关注成员的布局
    mblock_init(&netif_mblock, netif_buffer, sizeof(netif_t), 
                    NETIF_DEV_CNT, NLOCKER_NONE);
    
    netif_default = (netif_t *)0;

    plat_memset((void*)link_layers, 0, sizeof(link_layers));

    dbg_info(DBG_NETIF, "init done\n");
    return NET_ERR_OK;
}

net_err_t netif_register_layer(int type, const link_layer_t *layer) {
    if ((type < 0) || (type >= NETIF_TYPE_SIZE)) {
        dbg_error(DBG_NETIF, "type error");
        return NET_ERR_PARAM;
    }

    if (link_layers[type]) {
        dbg_error(DBG_NETIF, "link layer exist.\n");
        return NET_ERR_EXIST;
    }

    link_layers[type] = layer;
    return NET_ERR_OK;
}

static const link_layer_t *netif_get_layer(int type) {
    if ((type < 0) || (type >= NETIF_TYPE_SIZE)) {
        dbg_error(DBG_NETIF, "type error");
        return NET_ERR_PARAM;
    }

    return link_layers[type];
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

    netif->ops = ops;
    netif->ops_data = ops_data;//ops->open(允许在驱动接口中修改ops_data参数)

    //对网卡本身进行打开
    err = ops->open(netif, ops_data);
    if (err < 0) {
        dbg_error(DBG_NETIF, "netif ops open err.");
        goto free_return;
    }
    
    netif->state = NETIF_OPENED;

    //网卡驱动打开网卡存在问题
    if (netif->type == NETIF_TYPE_NONE) {
        dbg_error(DBG_NETIF, "netif type unknow.");
        goto free_return;
    }

    netif->link_layer = netif_get_layer(netif->type);
    if ((!netif->link_layer) && (netif->type != NETIF_TYPE_LOOP)) {
        dbg_error(DBG_NETIF, "no link layer netif name: %s\n", dev_name);
        goto free_return;
    }

    nlist_insert_last(&netif_list, &netif->node);

    display_netif_list();

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

net_err_t netif_set_addr(netif_t *netif, ipaddr_t *ip, ipaddr_t *netmask, ipaddr_t *gateway) {
    ipaddr_copy(&netif->ipaddr, ip ? ip : ipaddr_get_any());
    ipaddr_copy(&netif->netmask, netmask ? netmask : ipaddr_get_any());
    ipaddr_copy(&netif->gateway, gateway ? gateway : ipaddr_get_any());
    return NET_ERR_OK;
}
net_err_t netif_set_hwaddr(netif_t *netif, const char *hwaddr, int len) {
    plat_memcpy(netif->hwaddr.addr, hwaddr, len);
    netif->hwaddr.len = len;
    return NET_ERR_OK;
}

net_err_t netif_set_active(netif_t *netif) {
    if (netif->state != NETIF_OPENED) {
        dbg_error(DBG_NETIF, "netif is not opened.");
        return NET_ERR_STATE;
    }

    if (!netif_default && (netif->type != NETIF_TYPE_LOOP)) {
        netif_set_default(netif);
    }

    //激活后就可以使用协议栈了,那么在这里可以打开下层协议
    //(本质上就是初始化软件层面链路层的数据)
    if (netif->link_layer) {
        net_err_t err = netif->link_layer->open(netif);
        if (err < 0) {
            dbg_info(DBG_NETIF, "active error.\n");
            return err;
        }
    }

    netif->state = NETIF_ACTIVE;

    display_netif_list();

    return NET_ERR_OK;
}
net_err_t netif_set_deactive(netif_t *netif) {
    if (netif->state != NETIF_ACTIVE) {
        dbg_error(DBG_NETIF, "netif is not actived.");
        return NET_ERR_STATE;
    }

    //链路层协议的关闭
    if (netif->link_layer) {
        netif->link_layer->close(netif);
    }

    pktbuf_t *buf;
    while ((buf = fixq_recv(&netif->in_q, -1)) != (pktbuf_t *)0) {
        pktbuf_free(buf);
    }

    while ((buf = fixq_recv(&netif->out_q, -1)) != (pktbuf_t *)0) {
        pktbuf_free(buf);
    }

    //?
    if (netif_default == netif) {
        netif_default = (netif_t *)0;
    }

    netif->state = NETIF_OPENED;

    display_netif_list();

    return NET_ERR_OK;
}

net_err_t netif_close(netif_t *netif) {
    if (netif->state == NETIF_ACTIVE) {
        dbg_error(DBG_NETIF, "netif is active");
        return NET_ERR_STATE;
    }

    netif->ops->close(netif);
    netif->state = NETIF_CLOSED;
    nlist_remove(&netif_list, &netif->node);
    mblock_free(&netif_mblock, netif);
    display_netif_list();
    return NET_ERR_OK;
}
void netif_set_default(netif_t *netif) {
    netif_default = netif;
}

net_err_t netif_put_in(netif_t *netif, pktbuf_t *buf, int tmo) {
    net_err_t err = fixq_send(&netif->in_q, buf, tmo);
    if (err < 0) {
        dbg_warning(DBG_NETIF, "netif in_q full");
        return NET_ERR_FULL;
    }
    
    //通知工作线程,网卡接收到了一个数据包(这个通知实际是将一个通知消息放到一个队列里面)
    exmsg_netif_in(netif);

    return NET_ERR_OK;
}
pktbuf_t *netif_get_in(netif_t *netif, int tmo) {
    pktbuf_t *buf = fixq_recv(&netif->in_q, tmo);
    if (buf) {
        pktbuf_reset_acc(buf);
        return buf;
    }

    dbg_info(DBG_NETIF, "netif in_q empty");
    return (pktbuf_t *)0;
}
//往输出队列写
net_err_t netif_put_out(netif_t *netif, pktbuf_t *buf, int tmo) {
    net_err_t err = fixq_send(&netif->out_q, buf, tmo);
    if (err < 0) {
        dbg_warning(DBG_NETIF, "netif out_q full");
        return NET_ERR_FULL;
    }

    return NET_ERR_OK;
}

//从输出队列取出数据包,给网卡进行发送
pktbuf_t *netif_get_out(netif_t *netif, int tmo) {
    pktbuf_t *buf = fixq_recv(&netif->out_q, tmo);
    if (buf) {
        pktbuf_reset_acc(buf);
        return buf;
    }

    dbg_info(DBG_NETIF, "netif out_q empty");
    return (pktbuf_t *)0;
}

//往指定的网络接口(网卡)发送数据包
net_err_t netif_out(netif_t *netif, ipaddr_t *ipaddr, pktbuf_t *buf) {
    //放到网卡的队列中
    net_err_t err = netif_put_out(netif, buf, -1);//这里不需要等待,不能影响应用层发送数据
    if (err < 0) {
        dbg_info(DBG_NETIF, "send failed, queue full");
        return err;
    }

    //驱动网卡进行发送,xmit是由网卡驱动实现
    return netif->ops->xmit(netif);
}