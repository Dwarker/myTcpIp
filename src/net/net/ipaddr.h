#ifndef IPADDR_H
#define  IPADDR_H

#include <stdint.h>

#define IPV4_ADDR_SIZE  4

typedef struct _ipaddr_t {
    enum {
        IPADDR_V4,
    }type;
    union
    {
        uint32_t q_addr;
        uint8_t  a_addr[IPV4_ADDR_SIZE];
    };
}ipaddr_t;

//初始化时,填入缺省ip值
void ipaddr_set_any (ipaddr_t *ip);

#endif