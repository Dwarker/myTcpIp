#ifndef NLOCKER_H
#define NLOCKER_H

#include "sys_plat.h"
#include "net_err.h"

//锁的使用场景
typedef enum _nlocker_type_t {
    NLOCKER_NONE,
    NLOCKER_THREAD, //线程之间
}nlocker_type_t;

typedef struct _nlocker_t {
    nlocker_type_t type;

    union
    {
        sys_mutex_t mutex;
    };
    
}nlocker_t;

net_err_t nlocker_init (nlocker_t *locker, nlocker_type_t type);
void nlocker_destroy (nlocker_t *locker);
void nlocker_lock(nlocker_t *locker);
void nlocker_unlock(nlocker_t *locker);

#endif