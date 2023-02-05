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

int main (void) {
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