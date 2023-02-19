#include "ipaddr.h"

void ipaddr_set_any (ipaddr_t *ip) {
    ip->type = IPADDR_V4;
    ip->q_addr = 0;
}

net_err_t ipaddr_from_str (ipaddr_t *dest, const char *str) {
    if (!dest || !str) {
        return NET_ERR_PARAM;
    }

    uint8_t *p = dest->a_addr;
    uint8_t sub_addr = 0;
    char c;
    while ((c = *str++) != '\0') {
        if ((c >= '0') && (c <= '9')) {
            sub_addr = sub_addr * 10 + (c - '0');
        } else if (c == '.') {
            *p++ = sub_addr;
            sub_addr = 0;
        } else {
            return NET_ERR_PARAM;
        }
    }

    *p++ = sub_addr;
    return NET_ERR_OK;
}

ipaddr_t* ipaddr_get_any(void) {
    static ipaddr_t ipaddr_any = {.type = IPADDR_V4, .q_addr = 0 };
    return (ipaddr_t*)&ipaddr_any;
}

void ipaddr_copy(ipaddr_t *dest, ipaddr_t *src) {
    if (!dest || !src) {
        return;
    }

    dest->type = src->type;
    dest->q_addr = src->q_addr;
}