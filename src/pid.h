#ifndef _H_DEBUG_SERVER_PID_
#define _H_DEBUG_SERVER_PID_

#include <sys/signalfd.h>

extern int service_pid;
extern int gdbserver_pid;
extern int strace_pid;

extern sigset_t old_mask;

#endif