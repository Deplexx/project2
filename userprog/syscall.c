#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/stdbool.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "../lib/kernel/list.h"
#include "../lib/kernel/hash.h"
#include "../threads/synch.h"
#include "../filesys/file.h"
#include "../filesys/filesys.h"
#include "process.h"
#include "../devices/shutdown.h"
#include "../devices/input.h"
#include "../threads/malloc.h"
#include "../threads/vaddr.h"

#define max_param 3
int syscall_param[max_param];

unsigned fd_counter;

struct lock lock_filesys;

struct file_def* find_file_def(int fd);

bool create(const char* file, unsigned initial_size);

bool remove(const char* file);

struct file_def{ /*contains all info of a currently opened file*/
  struct list_elem elem;
  unsigned hash_num;
  char* file_str;
  struct file* opened_file;
  int fd;
  tid_t tid;
};

struct list open_file_list;/*contains all currently opend files*/
struct list_elem* e;/*used for iterator*/


/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user_byte (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));

  return result;
}
 
/*same behavior as get_user_byte only now for a 32-bit int*/
static int
get_user_int (const uint32_t *uaddr) {
  int i;

  int ret;
  uint8_t *caddr = (uint8_t*) uaddr;
  char *cret = (char*) &ret;
  for(i = 0; i < sizeof(uint32_t); ++i) {
    if((cret[i] = get_user_byte(caddr)) == -1) {
      ret = -1;
      break;
    }
    
    ++caddr;
  }

  return ret;
}

void check_user_ptr(const void* ptr);

void check_user_ptr(const void* ptr){
  if (!is_user_vaddr(ptr)){
    exit(-1);
  } if (get_user_byte(ptr) == -1){
    exit(-1);
  }
}


/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user_byte (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/*same behavior as put_user_byte only now for a 32-bit int*/
static bool
put_user_int (uint32_t *udst, uint32_t fourBytes) {
  int i;

  bool ret;
  uint8_t *caddr = (uint8_t*) udst;
  char *cwrt = (char*) &fourBytes;
  for(i = 0; i < sizeof(uint32_t); ++i) {
    if(!(ret = put_user_byte(caddr, cwrt[i]))) {
      break;
    }
    
    ++caddr;
  }

  return ret;
}


static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init(&lock_filesys);
  fd_counter = 2; /*initialze fd and open_file list*/
  list_init (&open_file_list);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void get_syscall_arg(int* esp, int num){
  int* param_ptr;
  int i;
  for (i=0;i<num;i++){
    param_ptr = esp + i + 1;
    if (!is_user_vaddr(param_ptr)){
      exit(-1);
    }
    syscall_param[i] = *param_ptr;
  }
}

/*
	f->eax = sysTab[syscall number](arg1, arg2, arg3,...);

*/
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_num;
  if(is_user_vaddr(f->esp)) {
    if((syscall_num = get_user_int(f->esp)) == -1) {
      exit(-1);
    }
  } else {
    exit(-1);
  }

  if ((syscall_num > SYS_INUMBER) || (syscall_num < SYS_HALT)){
    exit(-1);
  }

  switch(syscall_num) {
    case SYS_HALT:                   
      halt();
      break;
    case SYS_EXIT:               
      get_syscall_arg((int*)f->esp,1);
      exit(syscall_param[0]);
      break;
    case SYS_EXEC:                   
      get_syscall_arg((int*)f->esp,1);
      f->eax = (int)exec((const char*)syscall_param[0]);
      break;
    case SYS_WAIT:                 
      get_syscall_arg((int*)f->esp,1);
      f->eax = wait((pid_t)syscall_param[0]);
      break;
    case SYS_CREATE:                
      get_syscall_arg((int*)f->esp,2);
      f->eax = (int)create((const char*)syscall_param[0],(unsigned)syscall_param[1]);
      break;
    case SYS_REMOVE:                
      get_syscall_arg((int*)f->esp,1);
      f->eax = (int)remove((const char*)syscall_param[0]);
      break;
    case SYS_OPEN:             
      get_syscall_arg((int*)f->esp,1);
      f->eax = open((const char*)syscall_param[0]);
      break;
    case SYS_FILESIZE:           
      get_syscall_arg((int*)f->esp,1);
      f->eax = filesize(syscall_param[0]);
      break;
    case SYS_READ:                
      get_syscall_arg((int*)f->esp,3);
      f->eax = read(syscall_param[0],(void*)syscall_param[1],(unsigned)syscall_param[2]);
      break;
   case SYS_WRITE:              
      get_syscall_arg((int*)f->esp,3);
      f->eax = write(syscall_param[0],(const void*)syscall_param[1],(unsigned)syscall_param[2]);
      break;
    case SYS_SEEK:                 
      get_syscall_arg((int*)f->esp,2);
      seek(syscall_param[0],(unsigned)syscall_param[1]);
      break;
    case SYS_TELL:                  
      get_syscall_arg((int*)f->esp,1);
      f->eax = (unsigned)tell(syscall_param[0]);
      break;
    case SYS_CLOSE:             
      get_syscall_arg((int*)f->esp,1);
      close(syscall_param[0]);
      break;
    default:
      break;
   }
}

void halt(void){
  shutdown_power_off();
}

void exit(int status) {
  thread_current()->exit_status = status;

  /*close same file in linklist, call close function*/
  for(e = list_begin(&open_file_list);e != list_end(&open_file_list);e = list_next(e))  {
    struct file_def* fp = list_entry(e,struct file_def, elem);
    if(thread_tid() == fp->tid) {
      close(fp->fd);
      break;
    }
  }

  thread_exit();
}

int exec(const char* cmd_line){
  tid_t tid;
  check_user_ptr(cmd_line);
  tid = process_execute(cmd_line);
  return tid;
}

int wait(int pid){
  int retval = process_wait(pid);
  return retval;
}

bool create(const char* file, unsigned initial_size){
  if(file == NULL) { exit(-1);}
  lock_acquire(&lock_filesys);	/*declares ownership of filesys*/
  check_user_ptr(file);
  bool retval = filesys_create(file,initial_size);
  lock_release(&lock_filesys);  /*release ownership*/
  return retval;
}

bool remove(const char* file){
  /*lock_acquire(&lock_filesys);
  bool retval = filesys_remove(file);
  unsigned cur_hash_num = hash_string(file);

  remove all associated file_def in list*/
  /*for(e = list_begin(&open_file_list);e != list_end(&open_file_list);e = list_next(e))  {
    struct file_def* fp = list_entry(e,struct file_def, elem);
    if (cur_hash_num == fp->hash_num){
      if (strcmp(file,fp->file_str)==0){
	      list_remove(&(fp->elem));	
      }
    }
  }

  lock_release(&lock_filesys);
  return retval;  */

  return filesys_remove(file);
}

int open(const char* file){
  if (file == NULL) { 
    exit(-1);
    return -1;
  }
  check_user_ptr(file);
  lock_acquire(&lock_filesys);
  struct file *fp = filesys_open(file);
  unsigned cur_hash_num = hash_string(file);
  char* file_str_ptr = (char*)file;
  unsigned i = 0;

  if (fp == NULL) {
    lock_release(&lock_filesys);
    return -1;
  }

  /*maintain record for newly opened file*/
  struct file_def *cur_file = (struct file_def*)malloc(sizeof(struct file_def));    
  if (cur_file == NULL) {
    file_close(fp);
    lock_release(&lock_filesys);
    return -1;
  }
  cur_file->hash_num = cur_hash_num; 
  cur_file->file_str = (char*) malloc(15);

  cur_file->tid = thread_current()->tid;

  if (cur_file->file_str == NULL){
    free(cur_file);
    file_close(fp);
    lock_release(&lock_filesys);
    return -1;
  }

  for (i = 0; i < 15; i++){
    *(cur_file->file_str+i) = *(file_str_ptr+i);
  }

  cur_file->opened_file = fp;
  cur_file->fd = fd_counter;

  /*close same file in linklist, call close function*/
  for(e = list_begin(&open_file_list);e != list_end(&open_file_list);e = list_next(e))  {
    struct file_def* fp = list_entry(e,struct file_def, elem);
    if (cur_hash_num == fp->hash_num){
      if (strcmp(file,fp->file_str)==0){
        lock_release(&lock_filesys);
	close(fp->fd);	
        lock_acquire(&lock_filesys);
        break;
      }
    }
  }

  //add newly opened file to opened file list*/
  list_push_back(&open_file_list,&(cur_file->elem));

  /*fd_counter calculation*/
  ++fd_counter;
  if ((fd_counter == 0) || (fd_counter == 1)) fd_counter = 2;


  lock_release(&lock_filesys);
  return cur_file->fd;
}


  /*return the file_def struct with given fd*/
struct file_def* find_file_def(int fd){
  for(e = list_begin(&open_file_list);e != list_end(&open_file_list);e = list_next(e))  {
    struct file_def* fp = list_entry(e,struct file_def, elem);
      if (fd == fp->fd){
        return fp; 
    }
  }
  return NULL;
}

int filesize(int fd){
  int length;
  lock_acquire(&lock_filesys);
  struct file_def* fp = find_file_def(fd);
  if (fp == NULL){
    lock_release(&lock_filesys);
    return 0;
  }
  length = file_length(fp->opened_file);
  lock_release(&lock_filesys);
  return length;
}

int read(int fd, void* buffer,unsigned size){
  int32_t retval;
  if (size == 0) return 0;
  check_user_ptr(buffer);
  lock_acquire(&lock_filesys);
  /*read from keyboard*/
  if (fd == 0){
    uint8_t *buffer_ = (uint8_t *)buffer;
    unsigned int i;
    for (i=0;i<size;i++){
      *(buffer_+i) = input_getc();
    }
    lock_release(&lock_filesys);
    return size;
  }
  struct file_def* fp = find_file_def(fd);
   if (fp == NULL){
    lock_release(&lock_filesys);
    return 0;
  }
  retval = (int32_t)file_read(fp->opened_file,buffer,size);

  lock_release(&lock_filesys);
  return retval;
}

int write(int fd, const void* buffer, unsigned size){
  int32_t retval;
  unsigned counter = 0;
  if (size == 0) {return 0;}
  check_user_ptr(buffer);
  lock_acquire(&lock_filesys);
  /*write to console*/
  if (size == 0) return 0;
  if (fd == 1){
    /*call putbuf to putbuf()*/
    while(size > 512){
      putbuf((char*)buffer+counter,512);
      counter = counter + 512;
      size = size - 512;
    }
    putbuf((char*)buffer,size);
    lock_release(&lock_filesys);
    return size;
  }
  struct file_def* fp = find_file_def(fd);
   if (fp == NULL){
    lock_release(&lock_filesys);
    return 0;
  }
   retval = (int32_t)file_write(fp->opened_file,buffer,size);
  lock_release(&lock_filesys);
  
  return retval;
}

void seek(int fd, unsigned position){
  lock_acquire(&lock_filesys);
  struct file_def* fp = find_file_def(fd);
   if (fp == NULL){
    lock_release(&lock_filesys);
    return;
  }
 file_seek(fp->opened_file,position);
  lock_release(&lock_filesys);
}

unsigned tell(int fd){
  lock_acquire(&lock_filesys);
  int pos;
  struct file_def* fp = find_file_def(fd);
  if (fp == NULL){
    lock_release(&lock_filesys);
    return 0;
  }

  pos = file_tell(fp->opened_file);
  lock_release(&lock_filesys);
  return pos;
}

void close(int fd){
  lock_acquire(&lock_filesys);
  if ((fd==0) || (fd==1)) exit(-1);

  struct file_def* fp = find_file_def(fd);

  if (fp == NULL){
    lock_release(&lock_filesys);
    return;
  }

  if(fp->tid == thread_current()->tid) {
    /*close file*/
    file_close(fp->opened_file);

    /*remove from list*/
    list_remove(&(fp->elem));

    /*free memory*/
    free(fp->file_str);
    free(fp);
  } 

  lock_release(&lock_filesys);
}
