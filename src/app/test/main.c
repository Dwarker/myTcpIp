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
#include "net.h"
#include "dbg.h"
#include "nlist.h"
#include "mblock.h"
#include "pktbuf.h"

static sys_sem_t sem;
static sys_mutex_t mutex;
static int count;

static char buffer[100];
static int write_index, read_index;
static sys_sem_t read_sem, write_sem;

void thread1_entry (void *arg) {
	for (int i = 0; i < 2 * sizeof(buffer); i++) {
		sys_sem_wait(read_sem, 0);
		plat_printf("bbb\n");
		char data = buffer[read_index++];

		if (read_index >= sizeof(buffer)) {
			read_index = 0;
		}

		sys_sem_notify(write_sem);

		plat_printf("this is thread1: %d\n", data);

		sys_sleep(100);
	}
}

void thread2_entry (void *arg) {
	
	for (int i = 0; i < 2 * sizeof(buffer); i++) {
		sys_sem_wait(write_sem, 0);

		buffer[write_index++] = i;

		if (write_index >= sizeof(buffer)) {
			write_index = 0;
		}

		plat_printf("this is thread2: %d\n", i);

		sys_sem_notify(read_sem);
		plat_printf("AAA\n");
	}
}
#include "netif_pcap.h"

net_err_t netdev_init (void) {
	netif_pcap_open();
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
}

void basic_test(void) {
	nlist_test();
	mblock_test();
	pktbuf_test();
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
int main (void) {
	dbg_info(DBG_TEST, "info");
	dbg_warning(DBG_TEST, "warning");
	dbg_error(DBG_TEST, "error");

	#if 0
	sem1 = sys_sem_create(0);
	sys_thread_create(thread3_entry, "AAA");
	sys_thread_create(thread4_entry, "BBB");
	#endif

	//dbg_assert(1 == 1, "failed");
	//dbg_assert(1 == 0, "failed");

	#if 1
	net_init();

	basic_test();

	net_start();
	netdev_init();
	#endif

	while (1) {
		sys_sleep(10);
	};

	return 0;
}