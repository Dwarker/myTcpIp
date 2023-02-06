#ifndef TCP_ECHO_CLIENT_H
#define TCP_ECHO_CLIENT_H

//参数:ip 远端服务器IP, port 远端服务器端口
int tcp_echo_client_start(const char *ip, int port);

#endif