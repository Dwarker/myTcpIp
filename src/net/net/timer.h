#ifndef TIMER_H
#define TIMER_H

#include "net_cfg.h"
#include "net_err.h"
#include "nlist.h"

#define NET_TIMER_RELOAD    (1 << 0)

struct _net_timer_t;
typedef void (*timer_proc_t) (struct _net_timer_t *timer, void *arg);

typedef struct _net_timer_t {
    char name[TIMER_NAME_SIZE];
    int flags;
    int curr;   //剩余时间
    int reload;

    timer_proc_t proc;
    void *arg;
    nlist_node_t node;
}net_timer_t;

net_err_t net_timer_init(void);

//添加定时器
//net_timer_t *timer:要添加的定时器
net_err_t net_timer_add(net_timer_t *timer, const char *name, timer_proc_t proc,
                        void *arg, int ms, int flags);

void net_timer_remove(net_timer_t *timer);

//扫描定时器列表
net_err_t net_timer_check_tmo(int diff_ms);

//获取第一个定时器的时间
int net_timer_first_tmo(void);

#endif