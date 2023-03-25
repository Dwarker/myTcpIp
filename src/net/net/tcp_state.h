#ifndef TCP_STATE_H
#define TCP_STATE_H

#include "tcp.h"

const char *tcp_state_name(tcp_state_t state);
void tcp_set_state(tcp_t *tcp, tcp_state_t state);

#endif