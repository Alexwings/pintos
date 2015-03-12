#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/interrupt.h"

#define ERROR -1

#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2

struct child_process {
  int pid;
  int load;
  bool wait;
  int status;
  struct list_elem elem;
  struct semaphore sema;
  struct semaphore sema_load;
};

struct process_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

struct child_process* get_child_process (int pid);
struct file* process_get_file (int fd);
int user_to_kernel_ptr(const void *vaddr);
void parse_args (struct intr_frame *f, int *arg, int n);
void check_valid_buffer (void* buffer, unsigned size);

void syscall_init (void);

struct lock filesys_lock;

#endif /* userprog/syscall.h */
