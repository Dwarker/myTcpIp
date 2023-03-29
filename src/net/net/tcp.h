#ifndef TCP_H
#define TCP_H

#include "sock.h"
#include "net_cfg.h"
#include "pktbuf.h"
#include "dbg.h"

#pragma pack(1)
typedef struct _tcp_hdr_t {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    union 
    {
        uint16_t flag;
#if NET_ENDIAN_LITTLE
        struct {
            uint16_t resv : 4;
            uint16_t shdr : 4;
            uint16_t f_fin : 1;
            uint16_t f_syn : 1;
            uint16_t f_rst : 1;
            uint16_t f_psh : 1;
            uint16_t f_ack : 1;
            uint16_t f_urg : 1;
            uint16_t f_ece : 1;
            uint16_t f_cwr : 1;
        };
#else
        struct
        {
            uint16_t shdr : 4;
            uint16_t resv : 4;
            uint16_t f_cwr : 1;
            uint16_t f_ece : 1;
            uint16_t f_urg : 1;
            uint16_t f_ack : 1;
            uint16_t f_psh : 1;
            uint16_t f_rst : 1;
            uint16_t f_syn : 1;
            uint16_t f_fin : 1;
        };
        
#endif
    };
    uint16_t win;
    uint16_t checksum;
    uint16_t urgptr;
}tcp_hdr_t;

typedef struct _tcp_pkt_t {
    tcp_hdr_t hdr;
    uint8_t data[1]; //选项数据,一般用不到
}tcp_pkt_t;

#pragma pack()

typedef struct _tcp_seg_t {
    ipaddr_t local_ip;
    ipaddr_t remote_ip;
    tcp_hdr_t *hdr;
    pktbuf_t *buf;
    uint32_t data_len; //不包含tcp头部长度
    uint32_t seq; //数据包的序列号
    uint32_t seq_len;
}tcp_seg_t;

typedef enum _tcp_state_t {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECVD,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSING,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_LAST_ACK,
    TCP_STATE_MAX,
}tcp_state_t;

typedef struct _tcp_t {
    sock_t base;

    struct {
        uint32_t syn_out : 1;   //1 syn已经发送, 0 收到syn的ack回包 (就是重传作用)
        uint32_t irs_valid : 1; //收到对方的syn包(包含了初始序列号) 表明收到了对方的报文
    }flags;

    tcp_state_t state;

    //用于三次握手等待
    struct
    {
        sock_wait_t wait;
    }conn;

    //用于数据发送
    struct {
        uint32_t una; //unack 已发送,但是还未被对方确认接收的开始序号
        uint32_t nxt; //待发送的起始序号
        uint32_t iss; //初始序号

        sock_wait_t wait;//用于等待对方确认
    }snd;

    struct {
        uint32_t nxt; //希望接收到的序号,即已接收的最后一个字符后面的序号
        uint32_t iss; //初始序列号
        sock_wait_t wait; //用于等待对方发送数据过来
    }rcv;
    
}tcp_t;

#if DBG_DISP_ENABLED(DBG_TCP)
void tcp_show_info(char *msg, tcp_t *tcp);
void tcp_show_pkt(char *msg, tcp_hdr_t *tcp_hdr, pktbuf_t *buf);
void tcp_show_list(void);
#else
#define tcp_show_info(msg, tcp)
#define tcp_show_pkt(msg, hdr, buf)
#define tcp_show_list()
#endif

net_err_t tcp_init(void);
sock_t *tcp_create(int family, int protocol);
tcp_t *tcp_find(ipaddr_t *local_ip, uint16_t local_port, ipaddr_t *remote_ip, uint16_t remote_port);
net_err_t tcp_abort(tcp_t *tcp, net_err_t err);

static inline int tcp_hdr_size(tcp_hdr_t *hdr) {
    return hdr->shdr * 4;
}

static inline void tcp_set_hdr_size(tcp_hdr_t *hdr, int size) {
    hdr->shdr = size / 4;
}
#endif