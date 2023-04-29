#include <stdio.h>
#include <string.h>
#include "net_plat.h"
//#include <winsock2.h>
#include "net_api.h"

void download_test (const char *filename, int port) {
    printf("try to download %s from %s: %d\n", filename, friend0_ip, port);

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0) {
        printf("create socket failed.\n");
        return;
    }

    FILE *file = fopen(filename, "wb");
    if (file == (FILE *)0) {
        printf("open file failed.\n");
        goto failed;
    }

    struct sockaddr_in server_addr;
    plat_memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(friend0_ip);
    server_addr.sin_port = htons(port);
    if (connect(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        plat_printf("connect error\n");
        goto failed;
    }

    int keepalive = 1;
    int keepidle = 5;           // 空间一段时间后
    int keepinterval = 1;       // 时间多长时间
    int keepcount = 10;         // 重发多少次keepalive包
    setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive , sizeof(keepalive ));
    setsockopt(sockfd, SOL_TCP, TCP_KEEPIDLE, (void*)&keepidle , sizeof(keepidle ));
    setsockopt(sockfd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepinterval , sizeof(keepinterval ));
    setsockopt(sockfd, SOL_TCP, TCP_KEEPCNT, (void *)&keepcount , sizeof(keepcount ));

    ssize_t total_size = 0;
    char buf[8192] = {0};
    int rcv_size;
    while ((rcv_size = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
        fwrite(buf, 1, rcv_size, file);
        fflush(file);
        printf(".");
        total_size += rcv_size;
    }
    
    if (rcv_size < 0) {
        printf("rcv file size:%d\n", (int)total_size);
        goto failed;
    }
    printf("rcv file size:%d\nrcv file ok\n", (int)total_size);
    close(sockfd);
    fclose(file);
    return;
failed:
    printf("recv file\n");
    close(sockfd);
    if (file) {
        fclose(file);
    }
}