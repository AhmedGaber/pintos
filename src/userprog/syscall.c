#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <stdbool.h>
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/synch.h"

typedef uint32_t pid_t;

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
static int memread (void *src, void *des, size_t bytes);
static int32_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int fail_invalid_access(void);

void sys_halt (void);
void sys_exit (int status);
pid_t sys_exec (const char *cmdline);
int sys_wait(pid_t pid);
bool sys_write(int fd, const void *buffer, unsigned size, int* ret);
bool sys_create(const char* filename, unsigned initial_size);
bool sys_remove(const char* filename);


void
syscall_init (void)
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;
  ASSERT( sizeof(syscall_number) == 4 );

  // Check if the required memory is permmited.
  if (memread(f->esp, &syscall_number, sizeof(syscall_number)) == -1) {
    fail_invalid_access(); // invalid memory access attampet. Exit the user process.
  }

  printf ("DEBUG >>> System call number = %d.\n", syscall_number);

  /* Dispatch w.r.t system call number.
     All Constants are defined in /lib/syscall-nr.h */
  switch (syscall_number)
  {

  case SYS_HALT:
  {
    sys_halt();
    NOT_REACHED();
    break;
  }

  case SYS_EXIT:
  {
    int exitcode;
    if (memread(f->esp + 4, &exitcode, sizeof(exitcode)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    sys_exit(exitcode);
    NOT_REACHED();
    break;
  }

  case SYS_EXEC:
  {
    void* cmdline;
    if (memread(f->esp + 4, &cmdline, sizeof(cmdline)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    int out_code = sys_exec((const char*) cmdline);
    f->eax = (uint32_t) out_code;
    break;
  }

  case SYS_WAIT:
  {
    pid_t pid;
    if (memread(f->esp + 4, &pid, sizeof(pid_t)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    int ret = sys_wait(pid);
    f->eax = (uint32_t) ret;
    break;
  }

  case SYS_CREATE:
  {
    const char* filename;
    unsigned initial_size;
    bool out_code;
    if (memread(f->esp + 4, &filename, sizeof(filename)) == -1)
      fail_invalid_access(); // invalid memory access attampet.
    if (memread(f->esp + 8, &initial_size, sizeof(initial_size)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    out_code = sys_create(filename, initial_size);
    f->eax = out_code;
    break;
  }

  case SYS_REMOVE:
  {
    const char* filename;
    bool out_code;
    if (memread(f->esp + 4, &filename, sizeof(filename)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    out_code = sys_remove(filename);
    f->eax = out_code;
    break;
  }

  case SYS_OPEN:
  case SYS_FILESIZE:
  case SYS_READ:
  case SYS_WRITE:
  {
    int fd, out_code;
    const void *buffer;
    unsigned size;

    // TODO: write error messages
    if (memread(f->esp + 4, &fd, 4) == -1) fail_invalid_access();
    if (memread(f->esp + 8, &buffer, 4) == -1) fail_invalid_access();
    if (memread(f->esp + 12, &size, 4) == -1) fail_invalid_access();

    if (!sys_write(fd, buffer, size, &out_code)) fail_invalid_access();
    f->eax = (uint32_t) out_code;
    break;
  }

  case SYS_SEEK:
  case SYS_TELL:
  case SYS_CLOSE:

  /* unhandled case */
  default:
    printf("ERROR >>> System call %d is unimplemented.\n", syscall_number);
    fail_invalid_access();
    break;
  }

  fail_invalid_access ();
}

/*
* Suggested helper function feom the manual.
* Reads a byte at user virtual address UADDR. UADDR must be below PHYS_BASE.
* Returns the byte value if successful, -1 if a segfault occurred.
*/
static int32_t
get_user (const uint8_t *uaddr)
{
  // Check that a user pointer points under the PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE))
    return -1; // invalid memory access attampet.

  // as suggested in the manual
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/*
* From the manual, too.
* Writes BYTE to user address UDST. UDST must be below PHYS_BASE.
* Returns true if successful, false if a segfault occurred.
*/
static bool
put_user (uint8_t *udst, uint8_t byte)
{

  // Check that a user pointer points under the PHYS_BASE
  if (! ((void*)udst < PHYS_BASE))
    return 0; // invalid memory access attampet.

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/**
* Returns the number of bytes read, or -1 on page fault (invalid memory access attampet)
*/
static int
memread (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i = 0; i < bytes; i++) {
    value = get_user(src + i);
    if (value < 0)
      return -1; // invalid memory access attampet.
    *(char*)(dst + i) = value & 0xff; // from the manual.
  }
  return (int)bytes;
}

/**
* Failier-handler function in case of invalid memory access attampet.
*/
static int fail_invalid_access(void) {
  sys_exit (-1);
  NOT_REACHED();
}

/**
* Terminates Pintos by calling shutdown_power_off() (declared in
* ‘devices/shutdown.h’).
*/
void
sys_halt(void)
{
  shutdown_power_off(); // from devices/shutdown.h
}

/**
* Terminates the current user program, returning status to the kernel. If the
* process’s parent waits for it, this is the status that will be returned.
*/
void
sys_exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);

  // TODO
  fail_invalid_access();
}

/**
* Runs the executable whose name is given in cmd line, passing any
* given arguments, and returns the new process’s program id (pid).
*/
pid_t
sys_exec(const char *cmdline)
{
   printf("DEBUG >>> Exec : %s.\n", cmdline);
   while(true);

   // cmdline is the address to the character buffer on user memory
   // validation check is required
   if (get_user((const uint8_t*) cmdline) == -1) {
     fail_invalid_access();  // invalid memory access attampet
     return -1;
   }

   tid_t child_tid = process_execute(cmdline);
   return child_tid;
}

/**
* Waits for a child process pid and retrieves the child’s exit status.
*/
int
sys_wait(pid_t pid)
{
  printf ("DEBUG >>> Wait : %d.\n", pid);
  return process_wait(pid); // in process.c
}

/**
* Writes size bytes from buffer to the open file fd. Returns the number of
* bytes actually written, which may be less than size if some
* bytes could not be written.
*/
bool
sys_write(int fd, const void *buffer, unsigned size, int* ret)
{
   // Validation
   if (get_user((const uint8_t*) buffer) == -1) {
     fail_invalid_access(); // invalid
     return false;
   }

   // First, as of now, only implement fd=1 (stdout), it writes into the console.
   if(fd == 1) {
     putbuf(buffer, size);
     *ret = size;
     return true;
   }
   // TODO: implement the rest...
   else {
     printf("ERROR >>> sys_write unimplemented.\n");
   }
   return false;
}

/**
* Creates a new file called file initially initial size bytes in size.
* Returns true if successful, false otherwise.
*/
bool
sys_create(const char* filename, unsigned initial_size)
{
  bool out_code;
  if (get_user((const uint8_t*) filename) == -1) {  //validation
    return fail_invalid_access();
  }
  lock_acquire(&filesys_lock);
  out_code = filesys_create(filename, initial_size);
  lock_release(&filesys_lock);
  return out_code;
}

/**
* Deletes the file called file. Returns true if successful, false otherwise.
*/
bool
sys_remove(const char* filename)
{
  bool out_code;
  if (get_user((const uint8_t*) filename) == -1) {  //validation
    return fail_invalid_access();
  }
  lock_acquire(&filesys_lock);
  out_code = filesys_remove(filename);
  lock_release(&filesys_lock);
  return out_code;
}
