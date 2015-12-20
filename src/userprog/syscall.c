#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <stdbool.h>

static void syscall_handler (struct intr_frame *);
static int memread (void *src, void *des, size_t bytes);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;
  ASSERT( sizeof(syscall_number) == 4 );

  // Check if the required memory is permmited.
  if (memread(f->esp, &syscall_number, sizeof(syscall_number)) == -1) {
    thread_exit (); // invalid memory access attampet. Exit the user process.
    return;
  }

  printf ("DEBUG >>> System call number = %d\n", syscall_number);
  thread_exit ();
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
    if(value < 0)
      return -1; // invalid memory access attampet.
    *(char*)(dst + i) = value & 0xff; // from the manual.
  }
  return (int)bytes;
}
