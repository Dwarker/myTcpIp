#ifndef TCP_H
#define TCP_H

#include "sock.h"
#include "net_cfg.h"
#include "pktbuf.h"
#include "dbg.h"
#include "tcp.h"
#include "tcp_buf.h"
#include "timer.h"

#define TCP_DEFAULT_MSS     536

#define TCP_OPT_END     0
#define TCP_OPT_NOP     1  //表示填充的数据
#define TCP_OPT_MSS     2

#pragma pack(1)
typedef struct _tcp_opt_mss_t {
    uint8_t kind;
    uint8_t length;
    union {
        uint16_t mss;
    };
}tcp_opt_mss_t;

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
    TCP_STATE_FREE = 0,
    TCP_STATE_CLOSED,
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
        uint32_t fin_in : 1;    //表示是否数据接收真的完毕了
        uint32_t fin_out : 1;
        uint32_t irs_valid : 1; //收到对方的syn包(包含了初始序列号) 表明收到了对方的报文
        uint32_t keep_enable : 1;
    }flags;

    tcp_state_t state;

    int mss;

    //用于三次握手等待
    struct
    {
        sock_wait_t wait;
        int backlog;

        /*
        ----------|-------------|--------|------|
        正常通信    保活时间       保活间隔
        */
        int keep_idle;  //保活时间
        int keep_intvl; //保活间隔
        int keep_cnt;
        int keep_retry; //用于定时器发生时的计数

        net_timer_t keep_timer;
    }conn;

    //用于数据发送
    struct {
        tcp_buf_t buf;
        uint8_t data[TCP_SBUF_SIZE];//用于发送缓存,即tcp_buf_t中的data指向
        uint32_t una; //unack 已发送,但是还未被对方确认接收的开始序号
        uint32_t nxt; //待发送的起始序号
        uint32_t iss; //初始序号

        sock_wait_t wait;//用于等待对方确认
    }snd;

    struct {
        tcp_buf_t buf;
        uint8_t data[TCP_RBUF_SIZE];

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
void tcp_read_option(tcp_t *tcp, tcp_hdr_t *tcp_hdr);
int tcp_rcv_window(tcp_t *tcp);

static inline int tcp_hdr_size(tcp_hdr_t *hdr) {
    return hdr->shdr * 4;
}

static inline void tcp_set_hdr_size(tcp_hdr_t *hdr, int size) {
    hdr->shdr = size / 4;
}

//a <= b
#define TCP_SEQ_LE(a, b)    (((int32_t)(a) - (int32_t)(b)) <= 0)

//a < b
#define TCP_SEQ_LT(a, b)    (((int32_t)(a) - (int32_t)(b)) < 0)

void tcp_kill_all_timers(tcp_t *tcp);
void tcp_keepalive_start(tcp_t *tcp, int run);
void tcp_keepalive_restart(tcp_t *tcp);

#endif