#include "timer.h"
#include "dbg.h"
#include "sys.h"

static nlist_t timer_list;

#if DBG_DISP_ENABLED(DBG_TIMER)
static void display_timer_list(){
    plat_printf("----------timer list-----------\n");

    nlist_node_t *node;
    int index = 0;
    nlist_for_each(node, &timer_list) {
        net_timer_t *timer = nlist_entry(node, net_timer_t, node);

        plat_printf("%d: %s, period=%d, curr: %d ms, reload: %d ms\n",
                    index++, timer->name,
                    timer->flags & NET_TIMER_RELOAD ? 1 : 0,
                    timer->curr, timer->reload);
    }
    plat_printf("----------timer list end-----------\n");
}
#else
#define display_timer_list()
#endif

net_err_t net_timer_init(void) {
    dbg_info(DBG_TIMER, "timer init");

    nlist_init(&timer_list);

    dbg_info(DBG_TIMER, "time done");
    return NET_ERR_OK;
}

static void insert_timer(net_timer_t *insert) {
    nlist_node_t *node;

    nlist_for_each(node, &timer_list) {
        net_timer_t *curr = nlist_entry(node, net_timer_t, node);
        if (insert->curr > curr->curr) {
            insert->curr -= curr->curr;
        } else if (insert->curr == curr->curr) {
            insert->curr = 0;
            nlist_insert_after(&timer_list, node, &insert->node);
            return;
        } else {
            curr->curr -= insert->curr;

            nlist_node_t *pre = nlist_node_pre(&curr->node);
            if (pre) {
                nlist_insert_after(&timer_list, pre, &insert->node);
            } else {
                //若是第一个节点,则直接插入前方
                nlist_insert_fist(&timer_list, &insert->node);
            }
            return;
        }
    }

    //若没有找到位置,则直接插入尾部
    nlist_insert_last(&timer_list, &insert->node);
}

net_err_t net_timer_add(net_timer_t *timer, const char *name, timer_proc_t proc,
                        void *arg, int ms, int flags) {
    dbg_info(DBG_TIMER, "insert timer: %s", name);

    plat_strncpy(timer->name, name, TIMER_NAME_SIZE);
    timer->name[TIMER_NAME_SIZE - 1] = '\0';
    timer->reload = ms;
    timer->curr = ms;
    timer->proc = proc;
    timer->arg = arg;
    timer->flags = flags;

    //按升序插入链表,并对curr值进行调整
    insert_timer(timer);

    //nlist_insert_last(&timer_list, &timer->node);

    display_timer_list();

    return NET_ERR_OK;
}

void net_timer_remove(net_timer_t *timer) {
    dbg_info(DBG_TIMER, "remove timer: %s", timer->name);

    nlist_node_t *node;
    nlist_for_each(node, &timer_list) {
        //若该定时器未在定时器链表中,则跳过
        net_timer_t *curr = nlist_entry(node, net_timer_t, node);
        if (curr != timer) {
            continue;
        }

        nlist_node_t *next = nlist_node_next(&timer->node);
        if (next) {
            net_timer_t *next_timer = nlist_entry(next, net_timer_t, node);
            next_timer->curr += timer->curr;
        }
        //因为是双向链表,所以可以直接删除而不用遍历
        nlist_remove(&timer_list, &timer->node);
        break;
    }

    display_timer_list();
}

net_err_t net_timer_check_tmo(int diff_ms) {
    nlist_t wait_list;
    nlist_init(&wait_list);

    nlist_node_t *node = nlist_first(&timer_list);
    while (node) {
        nlist_node_t *next = nlist_node_next(node);

        net_timer_t *timer = nlist_entry(node, net_timer_t, node);
        if (timer->curr > diff_ms) {
            timer->curr -= diff_ms;
            break;
        }

        //如果相减后的值大于0,说明后面还有定时器可能也到时间了,仍需遍历,
        diff_ms -= timer->curr;

        //curr <= diff_ms
        timer->curr = 0;
        //移除当前定时器
        nlist_remove(&timer_list, &timer->node);
        //将该定时器插入延时链表中
        nlist_insert_last(&wait_list, &timer->node);
        //在这里不执行定时器函数,因为定时器函数中可能会添加移除定时器,
        //可能会出现问题,所以将待执行的定时器函数放到一个等待列表中
        //继续查看后面的定时器是否也到时间了
        
        node = next;
    }

    while ((node = nlist_remove_first(&wait_list)) != (nlist_node_t *)0) {
        net_timer_t *timer = nlist_entry(node, net_timer_t, node);

        timer->proc(timer, timer->arg);

        //如果是周期性定时器,则加回到定时器链表中
        if (timer->flags & NET_TIMER_RELOAD) {
            timer->curr = timer->reload;
            insert_timer(timer);
        }
    }
    
    display_timer_list();

    return NET_ERR_OK;
}