#ifndef ICMPV4_H
#define ICMPV4_H

#include "netif.h"
#include "pktbuf.h"

net_err_t icmpv4_init(void);
net_err_t icmpv4_in(ipaddr_t *src_ip, ipaddr_t *netif_in, pktbuf_t *buf);

#endif