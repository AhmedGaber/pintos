#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>

void syscall_init (void);

struct child_process{
  pid_t pid;
  struct list_elem elem;
  struct semaphore wait_load;
  struct semaphore waiting;
  int loaded;
  bool exited;
  bool wait;
  int exit_state;
}

struct file_desc {
  int id;
  struct list_elem elem;
  struct file* file;
};

#endif /* userprog/syscall.h */
