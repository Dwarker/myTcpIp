#include "ipaddr.h"

void ipaddr_set_any (ipaddr_t *ip) {
    ip->type = IPADDR_V4;
    ip->q_addr = 0;
}

int ipaddr_is_any(ipaddr_t *ip) {
    return ip->q_addr == 0;
}

net_err_t ipaddr_from_str (ipaddr_t *dest, const char *str) {
    if (!dest || !str) {
        return NET_ERR_PARAM;
    }

    dest->type = IPADDR_V4;
    dest->q_addr = 0;

    // 192.168.74.1
    // "192" -> 192 -> dest->a_addr[0]
    uint8_t * p = dest->a_addr;
    uint8_t sub_addr = 0;
    char c;
    while ((c = *str++) != '\0') {
        // '1' -> '9'
        if ((c >= '0') && (c <='9')) {  // 012345..9
            sub_addr = sub_addr * 10 + (c - '0');        // 10 + 9 => 190 + 2 = 192
        } else if (c == '.') {
            *p++ = sub_addr;
            sub_addr = 0;
        } else {
            return NET_ERR_PARAM;
        }
    }

    *p = sub_addr;
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

int ipaddr_is_equal(const ipaddr_t *ipaddr1, const ipaddr_t *ipaddr2) {
    return ipaddr1->q_addr == ipaddr2->q_addr;
}

void ipaddr_to_buf(const ipaddr_t *src, uint8_t *in_buf) {
    *(uint32_t *)in_buf = src->q_addr;
}

void ipaddr_from_buf(ipaddr_t *dest, uint8_t *ip_buf) {
    dest->type = IPADDR_V4;
    dest->q_addr = *(uint32_t *)ip_buf;
}

int ipaddr_is_local_broadcast(const ipaddr_t *ipaddr) {
    return ipaddr->q_addr == 0xFFFFFFFF;
}

ipaddr_t ipaddr_get_host(const ipaddr_t *ipaddr, const ipaddr_t *netmask) {
    ipaddr_t hostid;
    hostid.q_addr = ipaddr->q_addr & ~netmask->q_addr;

    return hostid;
}

ipaddr_t ipaddr_get_net(const ipaddr_t *ipaddr, const ipaddr_t *netmask) {
    ipaddr_t netid;

    netid.q_addr = ipaddr->q_addr & netmask->q_addr;
    return netid;
}
int ipaddr_is_direct_broadcast(const ipaddr_t *ipaddr, const ipaddr_t *netmask) {
    ipaddr_t hostid = ipaddr_get_host(ipaddr, netmask);
    return hostid.q_addr == (0xFFFFFFFF & ~netmask->q_addr);
}

//本地ip, 74.255(定向广播) 255.255.255.255(本地广播)
int ipaddr_is_match(const ipaddr_t *dest, const ipaddr_t *src, const ipaddr_t *netmask) {
    ipaddr_t dest_netid = ipaddr_get_net(dest, netmask);
    ipaddr_t src_netid = ipaddr_get_net(src, netmask);//src

    if (ipaddr_is_local_broadcast(dest)) {
        return 1;
    }

    if (ipaddr_is_direct_broadcast(dest, netmask)
        && ipaddr_is_equal(&dest_netid, &src_netid)) {
        return 1;
    }

    return ipaddr_is_equal(dest, src);
}

int ipaddr_1_cnt(ipaddr_t *ip) {
    int cnt = 0;
    uint32_t addr = ip->q_addr;
    while (addr) {
        if (addr & 0x80000000) {
            cnt++;
        }

        addr <<= 1;
    }
    return cnt;
}