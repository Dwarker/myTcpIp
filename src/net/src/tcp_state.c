#include "tcp_state.h"

const char *tcp_state_name(tcp_state_t state) {
    static const char* state_name[] = {
        [TCP_STATE_CLOSED] = "CLOSED",
        [TCP_STATE_LISTEN] = "LISTEN",
        [TCP_STATE_SYN_SENT] = "SYN_SENT",
        [TCP_STATE_SYN_RECVD] = "SYN_RECVD",
        [TCP_STATE_ESTABLISHED] = "ESTABLISHED",
        [TCP_STATE_FIN_WAIT_1] = "FIN_WAIT_1",
        [TCP_STATE_FIN_WAIT_2] = "FIN_WAIT_2",
        [TCP_STATE_CLOSING] = "CLOSING",
        [TCP_STATE_TIME_WAIT] = "TIME_WAIT",
        [TCP_STATE_CLOSE_WAIT] = "CLOSE_WAIT",
        [TCP_STATE_LAST_ACK] = "LAST_ACK",
        [TCP_STATE_MAX] = "UNKNOW",
    };

    if (state > TCP_STATE_MAX) {
        state = TCP_STATE_MAX;
    }

    return state_name[state];
}

void tcp_set_state(tcp_t *tcp, tcp_state_t state) {
    tcp->state = state;
    tcp_show_info("tcp set state", tcp);
}