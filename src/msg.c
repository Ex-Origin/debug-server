#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "handler.h"
#include "fd.h"
#include "log.h"

int gdbserver_pipe_handler()
{
    char buf[0x100];
    memset(buf, 0, sizeof(buf));
    CHECK(read(gdbserver_pipe[0], buf, sizeof(buf)-1) != -1);
    gdbserver_output(buf);
    return 1;
}

int strace_pipe_handler()
{
    char buf[0x100];
    memset(buf, 0, sizeof(buf));
    CHECK(read(strace_pipe[0], buf, sizeof(buf)-1) != -1);
    strace_output(buf);
    return 1;
}
