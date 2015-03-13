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

struct child_process* get_child (int pid);
struct file* find_file(int fd);
int user_to_kernel(const void *vaddr);
void check_valid_buffer (void* buffer, unsigned size);
void check_args_1_0(struct intr_frame *f, int* arg);
void check_args_2_0(struct intr_frame *f, int* arg);
void check_args_1_1(struct intr_frame *f, int* arg);
void check_args_2_1(struct intr_frame *f, int* arg);
void check_args_3_1(struct intr_frame *f, int* arg);
void syscall_init (void);

struct lock file_lock;

#endif /* userprog/syscall.h */
