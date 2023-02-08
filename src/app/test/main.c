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

#define DBG_TEST DBG_LEVEL_INFO

int main (void) {
	dbg_info(DBG_TEST, "info");
	dbg_warning(DBG_TEST, "warning");
	dbg_error(DBG_TEST, "error");

	dbg_assert(1 == 1, "failed");
	dbg_assert(1 == 0, "failed");

	net_init();
	net_start();

	netdev_init();

	return 0;
}