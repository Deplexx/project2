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
};

struct list open_file_list;/*contains all currently opend files*/
struct list_elem* e;/*used for iterator*/

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{

  fd_counter = 2; /*initialze fd and open_file list*/
  list_init (&open_file_list);
  /*TODO:filesys_init needed?*/
  filesys_init(true);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int get_syscall_num(void){
  return -1;
}

static void get_syscall_arg(int* esp, int num){
  int* param_ptr;
  for (int i=0;i<num;i++){
    param_ptr = esp + i + 1;
    if (!is_user_vaddr(param_ptr)){
      exit(-1);
    }
    syscall_param[i] = *param_ptr;
  }
}

/*@Irene: use f->esp to access stack pointr and then you'll be able to access syscall number, and other argument there. 
	So do as follow:

	1) sp = f->esp

		|				|
		|				|
		|				|
		|				|
		|---------------|
sp --->	|syscall number |
		|---------------|
		|     arg 1		|
		|---------------|
		|     arg 3		|
		|---------------|
		|     arg 2		|
		'---------------'

	2) f->eax = sysTab[syscall number](arg1, arg2, arg3,......);

	Note: systab (i.e. syscall table) is our data structure for storing, and I think you defined it as file_def

*/
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");

  struct thread* cur_thread = thread_current();

  int syscall_num = get_syscall_num();/*TODO: find this number*/

  if ((syscall_num > SYS_INUMBER) || (syscall_num < SYS_HALT)){
    cur_thread->status = -1;
    thread_exit();
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
   }
}

void halt(void){
  shutdown_power_off();
}

void exit(int status){
  struct thread *cur_thread = thread_current(); 
  cur_thread->status = status;
  thread_exit();
}

int exec(const char* cmd_line){
  int retval = process_execute(cmd_line);
  return retval;
}

int wait(int pid){
  int retval = process_wait(pid);
  return retval;
}

bool create(const char* file, unsigned initial_size){
  lock_acquire(&lock_filesys);	/*declares ownership of filesys*/
  bool retval = filesys_create(file,initial_size);
  lock_release(&lock_filesys);  /*release ownership*/
  return retval;
}

bool remove(const char* file){
  lock_acquire(&lock_filesys);
  bool retval = filesys_remove(file);
  unsigned cur_hash_num = hash_string(file);

  /*remove all associated file_def in list*/
  for(e = list_begin(&open_file_list);e != list_end(&open_file_list);e = list_next(e))  {
    struct file_def* fp = list_entry(e,struct file_def, elem);
    if (cur_hash_num == fp->hash_num){
      if (strcmp(file,fp->file_str)==0){
	list_remove(&(fp->elem));	
      }
    }
  }

  lock_release(&lock_filesys);
  return retval;  
}

int open(const char* file){
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
  cur_file->hash_num = hash_string(file); 
  cur_file->file_str = (char*) malloc(sizeof(file));

  if (cur_file->file_str == NULL){
    free(cur_file);
    file_close(fp);
    lock_release(&lock_filesys);
    return -1;
  }
  
  while(file_str_ptr!=0){
    *(cur_file->file_str+i) = *(file_str_ptr+i);
    i++;
  }

  cur_file->opened_file = fp;
  cur_file->fd = fd_counter;

  //add newly opened file to opened file list*/
  list_push_back(&open_file_list,&(cur_file->elem));

  /*fd_counter calculation*/
  ++fd_counter;
  if ((fd_counter == 0) || (fd_counter == 1)) fd_counter = 2;

  /*close same file in linklist, call close function*/
  for(e = list_begin(&open_file_list);e != list_end(&open_file_list);e = list_next(e))  {
    struct file_def* fp = list_entry(e,struct file_def, elem);
    if (cur_hash_num == fp->hash_num){
      if (strcmp(file,fp->file_str)==0){
	close(fp->fd);	
	list_remove(&(fp->elem));	
      }
    }
  }


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
  lock_acquire(&lock_filesys);
  int32_t retval;
  /*read from keyboard*/
  if (fd == 0){
    uint8_t *buffer_ = (uint8_t *)buffer;
    for (unsigned i=0;i<size;i++){
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
  lock_acquire(&lock_filesys);
  int32_t retval;
  unsigned counter = 0;
  /*write to console*/
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
  struct file_def* fp = find_file_def(fd);

  if (fp == NULL){
    lock_release(&lock_filesys);
  }

  /*close file*/
  file_close(fp->opened_file);

  /*remove from list*/
  list_remove(&(fp->elem));

  /*free memory*/
  free(fp->file_str);
  free(fp);
  lock_release(&lock_filesys);
}
