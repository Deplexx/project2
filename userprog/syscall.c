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

bool create(const char* file, unsigned initial_size);

bool remove(const char* file);

int inumber(int fd);

bool isdir(int fd);

bool readdir(int fd, char* path);

bool chdir(char* path);

bool mkdir(char* path);

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

 //TODO add 4 more cases for subdirect
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
    case SYS_CHDIR:
      get_syscall_arg((int*)f->esp,1);
      f->eax = (unsigned)chdir(syscall_param[0]);
      break;
    case SYS_MKDIR:
      get_syscall_arg((int*)f->esp,1);
      f->eax = (unsigned)mkdir(syscall_param[0]);
      break;
    case SYS_READDIR:
      get_syscall_arg((int*)f->esp,2);
      f->eax = (unsigned)readdir(syscall_param[0], syscall_param[1]);
      break;
    case SYS_ISDIR:
      get_syscall_arg((int*)f->esp,1);
      f->eax = (unsigned)isdir(syscall_param[0]);
      break;
    case SYS_INUMBER:
      get_syscall_arg((int*)f->esp,1);
      f->eax = (unsigned)inumber(syscall_param[0]);
      break;
    default:
      break;
   }
}

void halt(void){
  shutdown_power_off();
}

void exit(int status) {
  struct thread* t = thread_current();
  t->exit_status = status;

  /*close same file in linklist, call close function*/
  for(e = list_begin(&(t->open_file_list));e != list_end(&(t->open_file_list));e = list_next(e))  {
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
  check_user_ptr(file);
  bool retval = filesys_create(file,initial_size, false);
  return retval;
}

bool remove(const char* file){
  return filesys_remove(file);
}

int open(const char* file){
  if (file == NULL) { 
    exit(-1);
    return -1;
  }
  check_user_ptr(file);
  struct file *fp = filesys_open(file);
  unsigned cur_hash_num = hash_string(file);
  char* file_str_ptr = (char*)file;
  unsigned i = 0;

  if (fp == NULL) {
    return -1;
  }

  struct thread* t = thread_current();

  /*maintain record for newly opened file*/
  struct file_def *cur_file = (struct file_def*)malloc(sizeof(struct file_def));    
  if (cur_file == NULL) {
    file_close(fp);
    return -1;
  }
  cur_file->hash_num = cur_hash_num; 
  cur_file->file_str = (char*) malloc(15);

  cur_file->tid = thread_current()->tid;

  if (cur_file->file_str == NULL){
    free(cur_file);
    file_close(fp);
    return -1;
  }

  for (i = 0; i < 15; i++){
    *(cur_file->file_str+i) = *(file_str_ptr+i);
  }

  cur_file->opened_file = fp;
  cur_file->fd = t->fd_counter;

  /*close same file in linklist, call close function*/
  for(e = list_begin(&(t->open_file_list));e != list_end(&(t->open_file_list));e = list_next(e))  {
    struct file_def* fp = list_entry(e,struct file_def, elem);
    if (cur_hash_num == fp->hash_num){
      if (strcmp(file,fp->file_str)==0){
	close(fp->fd);	
        break;
      }
    }
  }

  //add newly opened file to opened file list*/
  list_push_back(&(t->open_file_list),&(cur_file->elem));

  /*fd_counter calculation*/
  ++t->fd_counter;
  if ((t->fd_counter == 0) || (t->fd_counter == 1)) t->fd_counter = 2;


  return cur_file->fd;
}




int filesize(int fd){
  int length;
  struct thread* t = thread_current();
  struct file_def* fp = find_file_def(t, fd);
  if (fp == NULL){
    return 0;
  }
  length = file_length(fp->opened_file);
  return length;
}

int read(int fd, void* buffer,unsigned size){
  int32_t retval;
  if (size == 0) return 0;
  check_user_ptr(buffer);
  /*read from keyboard*/
  if (fd == 0){
    uint8_t *buffer_ = (uint8_t *)buffer;
    unsigned int i;
    for (i=0;i<size;i++){
      *(buffer_+i) = input_getc();
    }
    return size;
  }
  struct thread* t = thread_current();
  struct file_def* fp = find_file_def(t, fd);
   if (fp == NULL){
    return 0;
  }
  retval = (int32_t)file_read(fp->opened_file,buffer,size);

  return retval;
}

int write(int fd, const void* buffer, unsigned size){
  int32_t retval;
  unsigned counter = 0;
  if (size == 0) {return 0;}
  check_user_ptr(buffer);
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
    return size;
  }
  struct thread* t = thread_current();
  struct file_def* fp = find_file_def(t, fd);
   if (fp == NULL){
    return 0;
  }
   retval = (int32_t)file_write(fp->opened_file,buffer,size);
  
  return retval;
}

void seek(int fd, unsigned position){
  struct thread* t = thread_current();
  struct file_def* fp = find_file_def(t, fd);
   if (fp == NULL){
    return;
  }
 file_seek(fp->opened_file,position);
}

unsigned tell(int fd){
  int pos;
  struct thread* t = thread_current();
  struct file_def* fp = find_file_def(t, fd);
  if (fp == NULL){
    return 0;
  }

  pos = file_tell(fp->opened_file);
  return pos;
}

void close(int fd){
  if ((fd==0) || (fd==1)) exit(-1);

  struct thread* t = thread_current();
  struct file_def* fp = find_file_def(t, fd);

  if (fp == NULL){
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

}

bool mkdir(char* path){
  if (path == NULL) return false;
  check_user_ptr(path);
  bool retval = filesys_create(path,0,true);
  return retval;
}

bool chdir(char* path){return true;}

bool readdir(int fd, char* path){
  struct thread* t = thread_current();
  struct file_def* fp = find_file_def(t, fd);
 
  if (fp == NULL) return false;
  struct inode* inode = file_get_inode(fp->opened_file);
  if (inode == NULL) return false; 
  if (!inode_isdir(inode)) return false;

  //TODO: read dir 
}

bool isdir(int fd) {
  struct thread* t = thread_current();
  struct file_def* fp = find_file_def(t, fd);
 
  if (fp == NULL) return false;
  struct inode* inode = file_get_inode(fp->opened_file);
  if (inode == NULL) return false; 
  return inode_isdir(inode);
}

int inumber(int fd) {
  struct thread* t = thread_current();
  struct file_def* fp = find_file_def(t, fd);
 
  if (fp == NULL) return -1;
  struct inode* inode = file_get_inode(fp->opened_file);
  if (inode == NULL) return -1; 
  return inode_inumber(inode);
}


