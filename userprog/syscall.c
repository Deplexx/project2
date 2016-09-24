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
#include "../filesys/file.h"
#include "../filesys/filesys.h"

unsigned fd_counter;

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
  list_init (&open_file_list);
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

int exec(const char* cmd_line){return 0;}

int wait(int pid){return 0;}

bool create(const char* file, unsigned initial_size){
  lock_acquire(&lock_filesys);	//declares ownership of filesys
  bool retval = filesys_create(file,initial_size);
  lock_release(&lock_filesys);  //release ownership
  return retval;
}

bool remove(const char* file){
  lock_acquire(&lock_filesys);
  bool retval = filesys_remove(file);
  unsigned cur_hash_num = hash_string(file);

  //remove all associated file_def in list
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

  if (fp == NULL) {
    lock_release(&lock_filesys);
    return -1;
  }

  //maintain record for newly opened file
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
  
  //TODO: do not use strcpy
  strcpy(cur_file->file_str,file);
  cur_file->opened_file = fp;
  cur_file->fd = fd_counter;

  //add newly opened file to opened file list
  list_push_back(&open_file_list,&(cur_file->elem));

  //fd_counter calculation
  ++fd_counter;
  if ((fd_counter == 0) || (fd_counter == 1)) fd_counter = 2;

  //close same file in linklist, call close function
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


  //return the file_def struct with given fd
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
  //read from keyboard
  if (fd == 0){
    uint8_t *buffer_;
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
  //write to console
  if (fd == 1){
    //call putbuf to putbuf()
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
    return 0;
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

  //close file
  file_close(fp->opened_file);

  //remove from list
  list_remove(fp->opened_file);

  //free memory
  free(fp->file_str);
  free(fp);
  lock_release(&lock_filesys);
}

