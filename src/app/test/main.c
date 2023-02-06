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

	#if 0
	while (1) {
		sys_sleep(5000);
		sys_sem_wait(sem, 0);
		plat_printf("this is thread2: %s\n", (char *)arg);
	}
	#endif
}

int main (void) {
	sem = sys_sem_create(0);
	read_sem = sys_sem_create(0);
	write_sem = sys_sem_create(sizeof(buffer));

	mutex = sys_mutex_create();

	//sys_thread_create(thread1_entry, "AAA");
	//sys_thread_create(thread2_entry, "BBB");

	//tcp_echo_client_start(friend0_ip, 5000);
	tcp_echo_server_start(5000);

	pcap_t *pcap = pcap_device_open(netdev0_phy_ip, netdev0_hwaddr);
	while (pcap) {
		static uint8_t buffer[1024];
		static int counter = 0;
		//接收的数据包包头地址
		struct pcap_pkthdr *pkthdr;
		//从网卡获取的数据地址
		const uint8_t *pkt_data;

		plat_printf("begin test: %d\n", counter++);
		for (int i = 0; i < sizeof(buffer); i++) {
			buffer[i] = i;
		}

		//接收数据:如果没有数据, 会等待,所以该循环不需要利用sleep
		//达到避免过渡消耗CPU的作用
		if (pcap_next_ex(pcap, &pkthdr, &pkt_data) != 1) {
			continue;
		}

		//拷贝获取数据
		int len = pkthdr->len > sizeof(buffer) ? sizeof(buffer) : pkthdr->len;
		plat_memcpy(buffer, pkt_data, len);
		buffer[0] = 3;
		buffer[1] = 4;

		//发送数据给网卡
		if (pcap_inject(pcap, buffer, sizeof(buffer)) == -1) {
			plat_printf("pcap send: send packet failed %s\n", pcap_geterr(pcap));
			break;
		}
	}

	printf("Hello, world");
	return 0;
}