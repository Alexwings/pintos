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

#define MAX_ARGS 3
#define USER_VADDR_BOTTOM ((void *) 0x08048000)


static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int arg[MAX_ARGS];
  user_to_kernel_ptr((const void*) f->esp);
  switch (* (int *) f->esp)
    {
    case SYS_HALT:
      {
	halt(); 
	break;
      }
    case SYS_EXIT:
      {
	parse_args (f, &arg[0], 1);
	exit(arg[0]);
	break;
      }
    case SYS_EXEC:
      {
	parse_args (f, &arg[0], 1);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = exec((const char *) arg[0]); 
	break;
      }
    case SYS_WAIT:
      {
	parse_args (f, &arg[0], 1);
	f->eax = wait(arg[0]);
	break;
      }
    case SYS_CREATE:
      {
	parse_args (f, &arg[0], 2);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = create((const char *)arg[0], (unsigned) arg[1]);
	break;
      }
    case SYS_REMOVE:
      {
	parse_args(f, &arg[0], 1);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = remove((const char *) arg[0]);
	break;
      }
    case SYS_OPEN:
      {
	parse_args(f, &arg[0], 1);
	arg[0] = user_to_kernel_ptr((const void *) arg[0]);
	f->eax = open((const char *) arg[0]);
	break; 		
      }
    case SYS_FILESIZE:
      {
	parse_args(f, &arg[0], 1);
	f->eax = filesize(arg[0]);
	break;
      }
    case SYS_READ:
      {
	parse_args(f, &arg[0], 3);
	check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
	arg[1] = user_to_kernel_ptr((const void *) arg[1]);
	f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
	break;
      }
    case SYS_WRITE:
      { 
	parse_args(f, &arg[0], 3);
	check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
	arg[1] = user_to_kernel_ptr((const void *) arg[1]);
	f->eax = write(arg[0], (const void *) arg[1],
		       (unsigned) arg[2]);
	break;
      }
    case SYS_SEEK:
      {
	parse_args(f, &arg[0], 2);
	seek(arg[0], (unsigned) arg[1]);
	break;
      } 
    case SYS_TELL:
      { 
	parse_args(f, &arg[0], 1);
	f->eax = tell(arg[0]);
	break;
      }
    case SYS_CLOSE:
      { 
	parse_args(f, &arg[0], 1);
	close(arg[0]);
	break;
      }
    }
}

void halt (void)
{
  shutdown_power_off();
}

void exit (int status)
{
  struct thread *cur = thread_current();
  if (thread_alive(cur->parent))
    {
      cur->cp->status = status;
    }
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}

pid_t exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct child_process* cp = get_child_process(pid);
  ASSERT(cp);

  //Block the current thread if cp is not loaded yet.
  if (cp->load == NOT_LOADED)
    {
      sema_down(&cp->sema_load);
    }

  if (cp->load == LOAD_FAIL)
    {
      return ERROR;
    }
  return pid;
}

int wait (pid_t pid)
{
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size)
{
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool remove (const char *file)
{
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}

int open (const char *file)
{
  lock_acquire(&filesys_lock);
  struct file *f = filesys_open(file);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  
  //Allocate space for the process_file variable
  struct process_file *pf = malloc (sizeof (struct process_file));
  pf->file = f;
  pf->fd = thread_current ()->fd++;

  //Add this file to the file list of the current thread
  list_push_back (&thread_current ()->file_list, &pf->elem);

  lock_release(&filesys_lock);
  return pf->fd;
}

int filesize (int fd)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int size = file_length(f);
  lock_release(&filesys_lock);
  return size;
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
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int bytes = file_read(f, buffer, size);
  lock_release(&filesys_lock);
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
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  int bytes = file_write(f, buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

void seek (int fd, unsigned position)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return;
    }
  file_seek(f, position);
  lock_release(&filesys_lock);
}

unsigned tell (int fd)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return ERROR;
    }
  off_t offset = file_tell(f);
  lock_release(&filesys_lock);
  return offset;
}

void close (int fd)
{
  lock_acquire(&filesys_lock);
  
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

  lock_release(&filesys_lock);
}

int user_to_kernel_ptr(const void *vaddr)
{
  // Check if vaddr is in the range of user memory
  if (!is_user_vaddr (vaddr) || vaddr < USER_VADDR_BOTTOM)
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

struct file* process_get_file (int fd)
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

struct child_process* get_child_process (int pid)
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

void parse_args (struct intr_frame *f, int *arg, int n)
{
  // Assign arg using the values that esp points to
  int i;
  int *ptr;
  for (i = 0; i < n; i++)
    {
      ptr = (int *) f->esp + i + 1;
      user_to_kernel_ptr((const void *) ptr);
      arg[i] = *ptr;
    }
}

void check_valid_buffer (void* buffer, unsigned size)
{
  // Check if every byte's address is valid
  int i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    {
      user_to_kernel_ptr((const void *) local_buffer++);
    }
}
