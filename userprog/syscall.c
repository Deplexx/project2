#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "../lib/kernel/list.h"
#include "../lib/kernel/hash.h"
#include "../threads/synch.h"

struct lock lock_filesys;

struct file_def{ //contains all info of a currently opened file
  struct list_elem elem;
  unsigned hash_num;
  char* file_str;
  struct file* opened_file;
  int fd;
};

struct list open_file_list;//contains all currently opend files
struct list_elem* e;//used for iterator

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{

  fd_counter = 2; //initialze fd and open_file list 
  list_init (open_file_list);
  //TODO:filesys_init needed?
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");

  //TODO:add switch case for all different syscalls

  thread_exit ();
}

void halt(void){
  shutdown_power_off();
}

void exit(int status){}

int exec(const char* cmd_line){}

int wait(int pid){}

bool create(const char* file, unsigned initial_size){
  lock_acquire(&lock_filesys);	//declares ownership of filesys
  bool retval = filesys_create(file,initial_size);
  lock_release(&lock_filesys);  //release ownership
  return retval;
}

//TODO: remove all associated file_def in list
bool remove(const char* file){
  lock_acquire(&lock_filesys);
  bool retval = filesys_remove(file);
  lock_release(&lock_filesys);
  return retval;  
}

int open(const char* file){//TODO: need to close same file in linklist, call close function
  lock_acquire(&lock_filesys);
  file *fp = filesys_open(file);
  if (fp == NULL) return -1;

  //maintain record for newly opened file
  struct file_def *cur_file = (file_def*)malloc(sizeof(file_def));    
  if (cur_file == NULL) {
    file_close(fp);
    return -1;
  }
  (*cur_file)->hash_num = hash_string(file); 
  (*cur_file)->file_str = (char*) malloc(sizeof(file));

  if ((*cur_file)->file_str == NULL){
    free(cur_file);
    file_close(fp);
    return -1;
  }
  strcpy((*cur_file)->file_str,file);
  (*cur_file)->opened_file = fp;
  (*cur_file)->fd = fd_counter;

  //add newly opened file to opened file list
  list_push_back(&open_file_list,&((*cur_file)->elem));

  //fd_counter calculation
  ++fd_counter;
  if ((fd_counter == 0) || (fd_counter == 1)) fd_counter = 2;

  lock_release(&lock_filesys);
  return fd;
}


//TODO: to be implemented; return the file_def struct with given fd
struct file_def* find_file_def(int fd){}

int filesize(int fd){}

int read(int fd, void* buffer,unsigned size){}
/*
struct file_def{ //contains all info of a currently opened file
  struct list_elem elem;
  unsigned hash_num;
  char* file_str;
  struct file* opened_file;
  int fd;
};
*/

int write(int fd, const void* buffer, unsigned size){}

void seek(int fd, unsigned position){}

unsigned tell(int fd){}

void close(int fd){
  struct file_def* fp = find_file_def(fd);

  //close file
  file_close((*fp)->opened_file);

  //remove from list
  list_remove((*fp)->elem);

  //free memory
  free((*fp)->file_str);
  free(fp);
}

