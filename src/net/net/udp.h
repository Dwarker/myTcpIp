#ifndef UDP_H
#define UDP_H

#include "sock.h"
#include "pktbuf.h"

#pragma pack(1)
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

typedef struct _udp_t {
    sock_t base;

    nlist_t recv_list;  //网卡数据收上来后放到这里,唤醒应用程序去取
    sock_wait_t recv_wait;
}udp_t;

net_err_t udp_init(void);
sock_t *udp_create(int family, int protocol);
net_err_t udp_out(ipaddr_t *dest, uint16_t dport, ipaddr_t *src, uint16_t sport, pktbuf_t *buf);

#endif