#include "netif_pcap.h"
#include "sys_plat.h"
#include "net_err.h"
#include "exmsg.h"

//网卡数据接收线程
void recv_thread (void *arg) {
    plat_printf("recv thread is running...\n");

    while (1) {
        sys_sleep(1);
        exmsg_netif_in();
    }
    
}

//网卡数据发送线程
void xmit_thread (void *arg) {
    plat_printf("xmit thread is running...\n");

    while (1) {
        sys_sleep(1);
    }
    
}

net_err_t netif_pcap_open (void) {
    sys_thread_create(recv_thread, (void *)0);
    sys_thread_create(xmit_thread, (void *)0);
    return NET_ERR_OK;
}