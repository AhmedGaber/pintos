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
#include "lib/kernel/list.h"

typedef uint32_t pid_t;
struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
static int memread (void *src, void *des, size_t bytes);
static int32_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int fail_invalid_access(void);
static struct file_desc* get_file_desc(struct thread *, int fd);

void halt (void);
void exit (int status);
pid_t exec (const char *cmdline);
int wait(pid_t pid);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
bool create(const char* filename, unsigned initial_size);
bool remove(const char* filename);
int open(const char* file);
void close(int fd);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);


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
    halt();
    NOT_REACHED();
    break;
  }

  case SYS_EXIT:
  {
    int exitcode;
    if (memread(f->esp + 4, &exitcode, sizeof(exitcode)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    exit(exitcode);
    NOT_REACHED();
    break;
  }

  case SYS_EXEC:
  {
    void* cmdline;
    if (memread(f->esp + 4, &cmdline, sizeof(cmdline)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    int out_code = exec((const char*) cmdline);
    f->eax = (uint32_t) out_code;
    break;
  }

  case SYS_WAIT:
  {
    pid_t pid;
    if (memread(f->esp + 4, &pid, sizeof(pid_t)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    int ret = wait(pid);
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

    out_code = create(filename, initial_size);
    f->eax = out_code;
    break;
  }

  case SYS_REMOVE:
  {
    const char* filename;
    bool out_code;
    if (memread(f->esp + 4, &filename, sizeof(filename)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    out_code = remove(filename);
    f->eax = out_code;
    break;
  }

  case SYS_OPEN:
  {
    const char* filename;
    int out_code;

    if (memread(f->esp + 4, &filename, sizeof(filename)) == -1)
      fail_invalid_access(); // invalid memory access attampet.
    out_code = open(filename);
    f->eax = out_code;
    break;
  }

  case SYS_FILESIZE:
  {
    int fd, out_code;
    if (memread(f->esp + 4, &fd, sizeof(fd)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    out_code = filesize(fd);
    f->eax = out_code;
    break;
  }

  case SYS_READ:
  {
    int fd, out_code;
    void *buffer;
    unsigned size;

    if(memread(f->esp + 4, &fd, 4) == -1) fail_invalid_access();
    if(memread(f->esp + 8, &buffer, 4) == -1) fail_invalid_access();
    if(memread(f->esp + 12, &size, 4) == -1) fail_invalid_access();

    out_code = read(fd, buffer, size);
    f->eax = (uint32_t) out_code;
    break;
  }

  case SYS_WRITE:
  {
    int fd, out_code;
    const void *buffer;
    unsigned size;

    if (memread(f->esp + 4, &fd, 4) == -1) fail_invalid_access();
    if (memread(f->esp + 8, &buffer, 4) == -1) fail_invalid_access();
    if (memread(f->esp + 12, &size, 4) == -1) fail_invalid_access();

    out_code = write(fd, buffer, size);
    f->eax = (uint32_t) out_code;
    break;
  }

  case SYS_SEEK:
  {
    int fd;
    unsigned position;

    if(memread(f->esp + 4, &fd, sizeof fd) == -1) fail_invalid_access();
    if(memread(f->esp + 8, &position, sizeof position) == -1) fail_invalid_access();

    seek(fd, position);
    break;
  }

  case SYS_TELL:
  {
    int fd;
    unsigned out_code;

    if(memread(f->esp + 4, &fd, 4) == -1) fail_invalid_access();

    out_code = tell(fd);
    f->eax = (uint32_t) out_code;
    break;
  }

  case SYS_CLOSE:
  {
    int fd;
    if (memread(f->esp + 4, &fd, sizeof(fd)) == -1)
      fail_invalid_access(); // invalid memory access attampet.

    close(fd);
    break;
  }

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
static int
fail_invalid_access(void)
{
  exit (-1);
  NOT_REACHED();
}

/**
* Takes a file id ,and returns it's descriptor. Returns NULL otherwise.
*/
static struct file_desc*
get_file_desc(struct thread *t, int fd)
{
  ASSERT (t != NULL);
  struct file* output_file;
  int i;
  struct list_elem *e;

  if (fd < 3) {
    return NULL;
  }

  if(! list_empty(&t->file_descriptors)){
    for(e = list_begin(&t->file_descriptors);
        e != list_end(&t->file_descriptors); e = list_next(e))
    {
       struct file_desc *desc = list_entry(e, struct file_desc, elem);
       if(desc->id == fd){
         return desc;
      }
    }
  }

  return NULL;
}

/**
* Terminates Pintos by calling shutdown_power_off() (declared in
* ‘devices/shutdown.h’).
*/
void
halt(void)
{
  shutdown_power_off(); // from devices/shutdown.h
}

/**
* Terminates the current user program, returning status to the kernel. If the
* process’s parent waits for it, this is the status that will be returned.
*/
void
exit(int status)
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
exec(const char *cmdline)
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
wait(pid_t pid)
{
  printf ("DEBUG >>> Wait : %d.\n", pid);
  return process_wait(pid); // in process.c
}

/**
* Opens the file called file. Returns a nonnegative integer handle called
* "file descriptor" (fd), or -1 if the file could not be opened.
*/
int
open(const char* file)
{
  struct file* opened_file;
  struct file_desc* fd = palloc_get_page(0);

  if (get_user((const uint8_t*) file) == -1) {
    return fail_invalid_access();
  }

  opened_file = filesys_open(file);
  if (!opened_file)
    return -1;

  fd->file = opened_file;

  struct list* fd_list = &thread_current()->file_descriptors;
  if (list_empty(fd_list)) {
    // 0, 1, 2 are reserved for STDIN, STDOUT, STDERR (from the manual).
    fd->id = 3;
  }
  else {
    fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  return fd->id;
}

/**
* Returns the size, in bytes, of the file open as fd.
*/
int
filesize(int fd)
{
  struct file_desc* descriptor;

  if (get_user((const uint8_t*) fd) == -1) {
    fail_invalid_access();
  }

  descriptor = get_file_desc(thread_current(), fd);

  if(descriptor == NULL) {
    return -1;
  }

  return file_length(descriptor->file);
}

/**
* Reads size bytes from the file open as fd into buffer. Returns the number
* of bytes actually read (0 at end of file), or -1 if the file could not
* be read (due to a condition other than end of file).
*/
int
read(int fd, void *buffer, unsigned size)
{

  if (get_user((const uint8_t*) buffer) == -1) {
    fail_invalid_access();
   }

   if(fd == 0) { // stdin
     unsigned i;
     for(i = 0; i < size; i++) {
       ((uint8_t *)buffer)[i] = input_getc();
     }
     return size;
   }
   else {
     // read from file
     struct file_desc* file_d = get_file_desc(thread_current(), fd);

     if(file_d && file_d->file) {
       return file_read(file_d->file, buffer, size);
     }
     else // no such file
       return -1;
   }
}

/**
* Writes size bytes from buffer to the open file fd. Returns the number of
* bytes actually written, which may be less than size if some
* bytes could not be written.
*/
int
write(int fd, const void *buffer, unsigned size)
{
   // Validation
   if (get_user((const uint8_t*) buffer) == -1) {
     fail_invalid_access(); // invalid
     return false;
   }

   if(fd == 1) {
     putbuf(buffer, size);
     return size;
   }
   else {
    struct file_desc* file_d = get_file_desc(thread_current(), fd); // write to file.

    if(file_d && file_d->file) {
      return file_write(file_d->file, buffer, size);
    }
    else // no such file.
      return -1;
  }
}

/**
* Creates a new file called file initially initial size bytes in size.
* Returns true if successful, false otherwise.
*/
bool
create(const char* filename, unsigned initial_size)
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
remove(const char* filename)
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

/**
* Changes the next byte to be read or written in open file fd to position,
* expressed in bytes from the beginning of the file.
* (Thus, a position of 0 is the file's start.)
*/
void
seek(int fd, unsigned position)
{
  struct file_desc* file_d = get_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    file_seek(file_d->file, position);
  }
  else
    return;
}

/**
* Returns the position of the next byte to be read or written in open file fd,
* expressed in bytes from the beginning of the file.
*/
unsigned
tell(int fd)
{
  struct file_desc* file_d = get_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    return file_tell(file_d->file);
  }
  else
    return -1;
}

/**
* Closes file descriptor fd. Exiting or terminating a process implicitly closes
* all its open file descriptors, as if by calling this function for each one.
*/
void
close(int fd)
{
  struct file_desc* file_d = get_file_desc(thread_current(), fd);

  if(file_d && file_d->file) {
    file_close(file_d->file);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
   }
}
