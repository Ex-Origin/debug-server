#include "pid.h"

int service_pid     = -1;
int gdbserver_pid   = -1;
int strace_pid      = -1;

sigset_t old_mask;
