#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

void process_init(void);
tid_t process_execute (const char *prog);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void process_done(void);

#endif /* userprog/process.h */
