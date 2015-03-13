#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define ARGS 3
#define USER_BOTTOM ((void *) 0x08048000)


static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init(&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int arg[ARGS];
  user_to_kernel((const void*) f->esp);
  switch (* (int *) f->esp)
    {
    case SYS_HALT:
      {
	shutdown_power_off();
	break;
      }
    case SYS_EXIT:
      {
        check_args_1_0(f, arg);
	exit(arg[0]);
	break;
      }
    case SYS_EXEC:
      {
	check_args_1_1(f, arg);
	f->eax = exec((const char *) arg[0]); 
	break;
      }
    case SYS_WAIT:
      {
        check_args_1_0(f, arg);
	f->eax = process_wait(arg[0]);
	break;
      }
    case SYS_CREATE:
      {
        check_args_2_1(f, arg);
	f->eax = create((const char *)arg[0], (unsigned) arg[1]);
	break;
      }
    case SYS_REMOVE:
      {
        check_args_1_1(f, arg);
	f->eax = remove((const char *) arg[0]);
	break;
      }
    case SYS_OPEN:
      {
        check_args_1_1(f,arg);
	f->eax = open((const char *) arg[0]);
	break; 		
      }
    case SYS_FILESIZE:
      {
        check_args_1_0(f,arg);
	f->eax = filesize(arg[0]);
	break;
      }
    case SYS_READ:
      {
        check_args_3_1(f, arg);
	f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
	break;

      }
    case SYS_WRITE:
      { 
        check_args_3_1(f, arg);
	f->eax = write(arg[0], (const void *) arg[1],
		       (unsigned) arg[2]);
	break;
      }
    case SYS_SEEK:
      {
        check_args_2_0(f, arg);
	seek(arg[0], (unsigned) arg[1]);
	break;
      } 
    case SYS_TELL:
      { 
	check_args_1_0(f, arg);
	f->eax = tell(arg[0]);
	break;
      }
    case SYS_CLOSE:
      { 
        check_args_1_0(f, arg);
	close(arg[0]);
	break;
      }
    }
}

void check_args_1_0 (struct intr_frame *f, int* arg)
{
   int *ptr = (int *) f->esp +1;
   user_to_kernel((const void *) ptr);
   arg[0] = *ptr;
}

void check_args_2_0 (struct intr_frame *f, int* arg)
{
   int *ptr = (int *) f->esp +1;
   int *ptr2 = (int *) f->esp +2;
   user_to_kernel((const void *) ptr);
   user_to_kernel((const void *) ptr2);
   arg[0] = *ptr;
   arg[1] = *ptr2;
}

void check_args_1_1 (struct intr_frame *f, int* arg)
{
   int *ptr = (int *) f->esp +1;
   user_to_kernel((const void *) ptr);
   arg[0] = *ptr;
   arg[0] = user_to_kernel((const void *) arg[0]);
}

void check_args_2_1 (struct intr_frame *f, int* arg)
{
   int *ptr = (int *) f->esp +1;
   int *ptr2 = (int *) f->esp +2;
   user_to_kernel((const void *) ptr);
   user_to_kernel((const void *) ptr2);
   arg[0] = *ptr;
   arg[1] = *ptr2;
   arg[0] = user_to_kernel((const void *) arg[0]);
}

void check_args_3_1  (struct intr_frame *f, int* arg)
{
   int *ptr = (int *) f->esp +1;
   int *ptr2 = (int *) f->esp +2;
   int *ptr3 = (int *) f->esp +3;
   user_to_kernel((const void *) ptr);
   user_to_kernel((const void *) ptr2);
   user_to_kernel((const void *) ptr3);
   arg[0] = *ptr;
   arg[1] = *ptr2;
   arg[2] = *ptr3;
   check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
   arg[1] = user_to_kernel((const void *) arg[1]);
}


void halt (void)
{
  shutdown_power_off();
}

void exit (int status)
{
  struct thread *c = thread_current();
  if (thread_alive(c->parent))
    {
      c->cp->status = status;
    }
  printf ("%s: exit(%d)\n", c->name, status);
  thread_exit();
}

pid_t exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct child_process* child_pro = get_child(pid);
  ASSERT(child_pro);

  //Block the current thread if child_pro is not loaded yet.
  if (child_pro->load == NOT_LOADED)
    {
      sema_down(&child_pro->sema_load);
    }

  if (child_pro->load == LOAD_FAIL)
    {
      return ERROR;
    }
  return pid;
}

int wait (pid_t pid)
{
  return process_wait(pid);
}

bool create (const char *f, unsigned init_size)
{
  lock_acquire(&file_lock);
  bool success = filesys_create(f, init_size);
  lock_release(&file_lock);
  return success;
}

bool remove (const char *f)
{
  lock_acquire(&file_lock);
  bool success = filesys_remove(f);
  lock_release(&file_lock);
  return success;
}

int open (const char *f)
{
  lock_acquire(&file_lock);
  struct file *file = filesys_open(f);
  if (!file)
    {
      lock_release(&file_lock);
      return ERROR;
    }
  
  //Allocate space for the process_file variable
  struct process_file *pro_f = malloc (sizeof (struct process_file));
  pro_f->file = file;
  pro_f->fd = thread_current ()->fd++;

  //Add this file to the file list of the current thread
  list_push_back (&thread_current ()->file_list, &pro_f->elem);

  lock_release(&file_lock);
  return pro_f->fd;
}

int filesize (int fd)
{
  lock_acquire(&file_lock);
  struct file *f = find_file(fd);
  if (!f)
    {
      lock_release(&file_lock);
      return ERROR;
    }
  int length = file_length(f);
  lock_release(&file_lock);
  return length;
}

int read (int fd, void *buffer, unsigned size)
{
  // Read from keyboard
  if (fd == STDIN_FILENO)
    {
      unsigned i;
      uint8_t* local_buffer = (uint8_t *) buffer;
      for (i = 0; i < size; i++)
	{
	  local_buffer[i] = input_getc();
	}
      return size;
    }

  // Read from file
  lock_acquire(&file_lock);
  struct file *f = find_file(fd);
  if (!f)
    {
      lock_release(&file_lock);
      return ERROR;
    }
  int bytes = file_read(f, buffer, size);
  lock_release(&file_lock);
  return bytes;
}

int write (int fd, const void *buffer, unsigned size)
{
  // Write to screen
  if (fd == STDOUT_FILENO)
    {
      putbuf(buffer, size);
      return size;
    }

  // Write to file
  lock_acquire(&file_lock);
  struct file *f = find_file(fd);
  if (!f)
    {
      lock_release(&file_lock);
      return ERROR;
    }
  int bytes = file_write(f, buffer, size);
  lock_release(&file_lock);
  return bytes;
}

void seek (int fd, unsigned position)
{
  lock_acquire(&file_lock);
  struct file *f = find_file(fd);
  if (!f)
    {
      lock_release(&file_lock);
      return;
    }
  file_seek(f, position);
  lock_release(&file_lock);
}

unsigned tell (int fd)
{
  lock_acquire(&file_lock);
  struct file *f = find_file(fd);
  if (!f)
    {
      lock_release(&file_lock);
      return ERROR;
    }
  off_t offset = file_tell(f);
  lock_release(&file_lock);
  return offset;
}

void close (int fd)
{
  lock_acquire(&file_lock);
  
  // Remove this file from file list of current thread and free its space
  struct thread *cur = thread_current ();
  struct list_elem *next, *e = list_begin (&cur->file_list);

  while (e != list_end (&cur->file_list))
  {
    next = list_next(e);
    struct process_file *pf = list_entry (e, struct process_file, elem);
    if (fd == pf->fd)
    {
      file_close (pf->file);
      list_remove (&pf->elem);
      free (pf);
      e = next;
    }
  }

  lock_release(&file_lock);
}

int user_to_kernel(const void *vaddr)
{
  // Check if vaddr is in the range of user memory
  if (!is_user_vaddr (vaddr) || vaddr < USER_BOTTOM)
  {
    exit (ERROR);
  }
  
  // Look for vaddr in page directory of kernel
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
  {
    exit(ERROR);
  }
  return (int) ptr;
}

struct file* find_file(int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->file_list); e != list_end (&t->file_list);
       e = list_next (e))
        {
          struct process_file *pf = list_entry (e, struct process_file, elem);
          if (fd == pf->fd)
	    {
	      return pf->file;
	    }
        }
  return NULL;
}

struct child_process* get_child(int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->child_list); e != list_end (&t->child_list);
       e = list_next (e))
        {
          struct child_process *cp = list_entry (e, struct child_process, elem);
          if (pid == cp->pid)
	    {
	      return cp;
	    }
        }
  return NULL;
}

void check_valid_buffer (void* buffer, unsigned size)
{
  // Check if every byte's address is valid
  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    {
      user_to_kernel((const void *) local_buffer++);
    }
}
