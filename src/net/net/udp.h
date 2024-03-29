#ifndef UDP_H
#define UDP_H

#include "sock.h"
#include "pktbuf.h"

#pragma pack(1)
typedef struct _udp_from_t {
    ipaddr_t from;
    uint16_t port;
}udp_from_t;

typedef struct _udp_hdr_t {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t total_len;
    uint16_t checksum;
}udp_hdr_t;

typedef struct _udp_pkt_t {
    udp_hdr_t hdr;
    uint8_t data[1];
}udp_pkt_t;
#pragma pack()

//udp发送是不需要等待的,如果缓存区满了,则数据丢失,接收需要等待,因为可能数据还没到
typedef struct _udp_t {
    sock_t base;

    nlist_t recv_list;  //网卡数据收上来后放到这里,唤醒应用程序去取
    sock_wait_t recv_wait;
}udp_t;

net_err_t udp_init(void);
sock_t *udp_create(int family, int protocol);
net_err_t udp_out(ipaddr_t *dest, uint16_t dport, ipaddr_t *src, uint16_t sport, pktbuf_t *buf);

//src_ip:该数据报来自哪里 dest_ip:该数据报从哪个网卡接收的
net_err_t udp_in(pktbuf_t *buf, ipaddr_t *src_ip, ipaddr_t *dest_ip);
#endif