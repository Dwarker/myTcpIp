/**
 * @file main.c
 * @author wangxuan
 * @brief 测试主程序，完成一些简单的测试主程序
 * @version 0.1
 * @date 2023-02-05
 *
 */
#include <stdio.h>
#include <sys_plat.h>
#include "pcap.h"
#include "echo/tcp_echo_client.h"
#include "echo/tcp_echo_server.h"
#include "echo/udp_echo_client.h"
#include "echo/udp_echo_server.h"
#include "net.h"
#include "dbg.h"
#include "nlist.h"
#include "mblock.h"
#include "pktbuf.h"
#include "netif.h"
#include "netif_pcap.h"
#include "tools.h"
#include "timer.h"
#include "ipv4.h"

#include "ping/ping.h"

pcap_data_t netdev0_data = {.ip = netdev0_phy_ip, .hwaddr = netdev0_hwaddr};

net_err_t netdev_init (void) {
	dbg_info(DBG_NETIF, "init netif0");

    netif_t *netif = netif_open("netif0", &netdev_ops, &netdev0_data);
    if (!netif) {
        dbg_error(DBG_NETIF, "open netif error.");
        return NET_ERR_NONE;
    }

    ipaddr_t ip, mask, gw;
    ipaddr_from_str(&ip, netdev0_ip);
    ipaddr_from_str(&mask, netdev0_mask);
	ipaddr_from_str(&gw, netdev0_gw);

    netif_set_addr(netif, &ip, &mask, &gw);

    netif_set_active(netif);

	//pktbuf_t *buf = pktbuf_alloc(32);
	//pktbuf_fill(buf, 0x53, 32);

	//ipaddr_t dest, src;
	//ipaddr_from_str(&dest, friend0_ip);
	//ipaddr_from_str(&src, netdev0_ip);
	//netif_out(netif, &dest, buf);
	//ipv4_out(0, &dest, &src, buf);

	//ipaddr_from_str(&dest, "192.168.174.255");
	//buf = pktbuf_alloc(32);
	//pktbuf_fill(buf, 0xA5, 32);
	//netif_out(netif, &dest, buf);

    dbg_info(DBG_NETIF, "init done.");
	return NET_ERR_OK;
}

//基础组件--链表测试
typedef struct _tnode_t {
	int id;//测试方便观察
	nlist_node_t node;
}tnode_t;

void nlist_test(void) {
	#define NODE_CNT 4
	tnode_t node[NODE_CNT];
	nlist_t list;

	nlist_init(&list);
	for (int i = 0; i < NODE_CNT; i++) {
		node[i].id = i;
		nlist_insert_fist(&list, &node[i].node);
	}

	plat_printf("insert first\n");

	nlist_node_t *p;
	nlist_for_each(p, &list) {
		tnode_t *tnode = nlist_entry(p, tnode_t, node);
		plat_printf("id:%d\n", tnode->id);
	}

	plat_printf("remove first\n");
	for (int i = 0; i < NODE_CNT; i++) {
		p = nlist_remove_first(&list);
		plat_printf("id:%d\n", nlist_entry(p, tnode_t, node)->id);
	}

	for (int i = 0; i < NODE_CNT; i++) {
		node[i].id = i;
		nlist_insert_last(&list, &node[i].node);
	}

	plat_printf("insert last\n");
	nlist_for_each(p, &list) {
		tnode_t *tnode = nlist_entry(p, tnode_t, node);
		plat_printf("id:%d\n", tnode->id);
	}

	plat_printf("remove last\n");
	for (int i = 0; i < NODE_CNT; i++) {
		p = nlist_remove_last(&list);
		plat_printf("id:%d\n", nlist_entry(p, tnode_t, node)->id);
	}

	plat_printf("insert after\n");
	for (int i = 0; i < NODE_CNT; i++) {
		node[i].id = i;
		nlist_insert_after(&list, nlist_first(&list), &node[i].node);
	}

	nlist_for_each(p, &list) {
		tnode_t *tnode = nlist_entry(p, tnode_t, node);
		plat_printf("id:%d\n", tnode->id);
	}
}

void mblock_test(void) {
	mblock_t blist;
	static uint8_t buffer[100][10];

	mblock_init(&blist, buffer, 100, 10, NLOCKER_THREAD);

	void *temp[10];
	for (int i = 0; i < 10; i++) {
		temp[i] = mblock_alloc(&blist, 0);
		plat_printf("block: %p, free_count: %d\n", temp[i], mblock_free_cnt(&blist));
	}

	for (int i = 0; i < 10; i++) {
		mblock_free(&blist, temp[i]);
		plat_printf("free count: %d\n", mblock_free_cnt(&blist));
	}
	mblock_destroy(&blist);
}

void pktbuf_test() {
	pktbuf_t *buf = pktbuf_alloc(2000);
	pktbuf_free(buf);

	buf = pktbuf_alloc(2000);
	for (int i = 0; i < 16; i++) {
		pktbuf_add_header(buf, 33, 1);//连续包头添加测试
	}

	for (int i = 0; i < 16; i++) {
		pktbuf_remove_header(buf, 33);
	}

	for (int i = 0; i < 16; i++) {
		pktbuf_add_header(buf, 33, 0);//非连续包头添加测试
	}

	for (int i = 0; i < 16; i++) {
		pktbuf_remove_header(buf, 33);
	}
	pktbuf_free(buf);

	//测试包的扩大和缩小
	buf = pktbuf_alloc(8);
	pktbuf_resize(buf, 32);
	pktbuf_resize(buf, 288);
	pktbuf_resize(buf, 4922);
	pktbuf_resize(buf, 1921);
	pktbuf_resize(buf, 288);
	pktbuf_resize(buf, 32);
	pktbuf_resize(buf, 0);
	pktbuf_free(buf);

	//测试包的合并
	buf = pktbuf_alloc(689);
	pktbuf_t *sbuf = pktbuf_alloc(892);
	pktbuf_join(buf, sbuf);
	pktbuf_free(buf);

	//测试合并不连续的数据的数据包
	buf = pktbuf_alloc(32);
	pktbuf_join(buf, pktbuf_alloc(4));
	pktbuf_join(buf, pktbuf_alloc(16));
	pktbuf_join(buf, pktbuf_alloc(54));
	pktbuf_join(buf, pktbuf_alloc(32));
	pktbuf_join(buf, pktbuf_alloc(38));

	pktbuf_set_cont(buf, 44);//将不连续的44个字节合并
	pktbuf_set_cont(buf, 60);
	pktbuf_set_cont(buf, 44);
	pktbuf_set_cont(buf, 128);
	pktbuf_set_cont(buf, 135);
	pktbuf_free(buf);

	//测试数据访问
	buf = pktbuf_alloc(32);
	pktbuf_join(buf, pktbuf_alloc(4));
	pktbuf_join(buf, pktbuf_alloc(16));
	pktbuf_join(buf, pktbuf_alloc(54));
	pktbuf_join(buf, pktbuf_alloc(32));
	pktbuf_join(buf, pktbuf_alloc(38));
	pktbuf_join(buf, pktbuf_alloc(512));
	pktbuf_join(buf, pktbuf_alloc(1000));

	pktbuf_reset_acc(buf);

	static uint16_t temp[1000];
	for (int i = 0; i < 1000; i++) {
		temp[i] = i;
	}
	pktbuf_write(buf, (uint8_t*)temp, pktbuf_total(buf));

	static uint16_t read_tmp[1000];
	plat_memset(read_tmp, 0, sizeof(read_tmp));

	//从数据包的开始
	pktbuf_reset_acc(buf);
	pktbuf_read(buf, (uint8_t *)read_tmp, pktbuf_total(buf));
	if (plat_memcmp(temp, read_tmp, pktbuf_total(buf)) != 0) {
		plat_printf("not equal");
		return;
	}

	//测试数据包定位
	plat_memset(read_tmp, 0, sizeof(read_tmp));
	pktbuf_seek(buf, 18 * 2);
	pktbuf_read(buf, (uint8_t *)read_tmp, 56);
	if (plat_memcmp(temp + 18, read_tmp, 56) != 0) {
		plat_printf("not equal");
		return;
	}

	//测试跨数据块定位
	plat_memset(read_tmp, 0, sizeof(read_tmp));
	pktbuf_seek(buf, 85 * 2);
	pktbuf_read(buf, (uint8_t *)read_tmp, 256);
	if (plat_memcmp(temp + 85, read_tmp, 256) != 0) {
		plat_printf("not equal");
		return;
	}

	pktbuf_t *dest = pktbuf_alloc(1024);
	pktbuf_seek(dest, 600);
	pktbuf_seek(buf, 200);
	pktbuf_copy(dest, buf, 122);

	plat_memset(read_tmp, 0, sizeof(read_tmp));
	pktbuf_seek(dest, 600);
	pktbuf_read(dest, (uint8_t *)read_tmp, 122);
	if (plat_memcmp(temp + 100, read_tmp, 122) != 0) {
		plat_printf("not equal");
		return;
	}

	pktbuf_seek(dest, 0);
	pktbuf_fill(dest, 53, pktbuf_total(dest));
	plat_memset(read_tmp, 0, sizeof(read_tmp));
	pktbuf_seek(dest, 0);
	pktbuf_read(dest, (uint8_t *)read_tmp, pktbuf_total(dest));

	char *ptr = (char *)read_tmp;
	for (int i = 0; i < pktbuf_total(dest); i++) {
		if (*ptr++ != 53) {
			plat_printf("not equal");
			return;
		}
	}

	pktbuf_free(dest);
	pktbuf_free(buf);
}

void timer0_proc (struct _net_timer_t *timer, void *arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer1_proc (struct _net_timer_t *timer, void *arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer2_proc (struct _net_timer_t *timer, void *arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer3_proc (struct _net_timer_t *timer, void *arg) {
	static int count = 1;
	printf("this is %s: %d\n", timer->name, count++);
}

void timer_test() {
	static net_timer_t t0, t1, t2, t3;

	net_timer_add(&t0, "t0", timer0_proc, (void *)0, 200, 0);
	net_timer_add(&t1, "t1", timer1_proc, (void *)0, 1000, NET_TIMER_RELOAD);
	net_timer_add(&t2, "t2", timer2_proc, (void *)0, 1000, NET_TIMER_RELOAD);
	net_timer_add(&t3, "t3", timer3_proc, (void *)0, 4000, NET_TIMER_RELOAD);

	net_timer_remove(&t1);
}

void basic_test(void) {
	nlist_test();
	mblock_test();
	pktbuf_test();

	uint32_t v1 = x_ntohl(0x12345678);
	uint16_t v2 = x_ntohs(0x1234);

	timer_test();
}

#define DBG_TEST DBG_LEVEL_INFO

#if 0
static sys_sem_t sem1;
void thread3_entry (void *arg) {
	while (1) {
		//plat_printf("3\n");
		sys_sem_notify(sem1);
	}
}

void thread4_entry (void *arg) {
	while (1) {
		sys_sem_wait(sem1, 0);
		plat_printf("4\n");
	}
}
#endif

net_err_t test_func(struct _func_msg_t *msg);

int main (void) {
	//dbg_info(DBG_TEST, "info");
	//dbg_warning(DBG_TEST, "warning");
	//dbg_error(DBG_TEST, "error");

	#if 0
	sem1 = sys_sem_create(0);
	sys_thread_create(thread3_entry, "AAA");
	sys_thread_create(thread4_entry, "BBB");
	#endif

	//dbg_assert(1 == 1, "failed");
	//dbg_assert(1 == 0, "failed");

	#if 1
	net_init();

	//basic_test();
	netdev_init();
	net_start();

	#endif

	udp_echo_server_start(2000);
	udp_echo_client_start("127.0.0.1", 2000);

	//请求协议栈执行某函数,这里是请求执行test_func
	int arg = 0x1234;
	exmsg_func_exec(test_func, &arg);

	ping_t p;
	//ping_run(&p, friend0_ip, 4, 64, 1000);
	ping_run(&p, "8.8.8.8", 4, 64, 1000);
	
	char cmd[32], param[32];
	while (1) {
		printf(">>");
		scanf("%s%s", cmd, param);
		if (strcmp(cmd, "ping") == 0) {
			ping_run(&p, param, 4, 1000, 1000);
		}
	};

	return 0;
}