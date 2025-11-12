#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

typedef int mapid_t;

void syscall_init (void);

extern struct lock filesys_lock;

void thread_exit_with_status(int status);
void do_munmap(mapid_t mapping);

#endif /* userprog/syscall.h */
