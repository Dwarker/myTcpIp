#include "arp.h"
#include "dbg.h"
#include "mblock.h"

static arp_entry_t cache_tbl[ARP_CACHE_SIZE];
static mblock_t cache_mblock;//用于对cache_tbl的分配
static nlist_t cache_list;//存放正在arp查询或者已经查询的arp

//arp缓存表的初始化
static net_err_t cache_init(void) {
    nlist_init(&cache_list);
    net_err_t err = mblock_init(&cache_mblock, cache_tbl, sizeof(arp_entry_t), ARP_CACHE_SIZE, NLOCKER_NONE);
    if (err < 0) {
        return err;
    }
    return NET_ERR_OK;
}

net_err_t arp_init() {
    net_err_t err = cache_init();
    if (err < 0) {
        dbg_error(DBG_ARP, "arp cache init failed.");
        return err;
    }

    return NET_ERR_OK;
}