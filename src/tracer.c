#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include "debug-server.h"

char *gdbserver_args[]  = {"gdbserver", "--attach", /* Reserved parameter */ NULL, NULL, NULL};
char *strace_args[]     = {"strace", "-f", "-p", /* Reserved parameter */ NULL, NULL};

int gdbserver_attach_pid(int pid)
{
    char arg1[0x100], arg2[0x100];
    char buf[0x200];
    int run = 0;
    int result = 0;
    
    memset(arg1, 0, sizeof(arg1));
    memset(arg2, 0, sizeof(arg2));
    if (arg_opt_6)
    {
        snprintf(arg1, sizeof(arg1)-1, ":::%d", GDBSERVER_PORT);
    }
    else
    {
        snprintf(arg1, sizeof(arg1)-1, "0.0.0.0:%d", GDBSERVER_PORT);
    }
    snprintf(arg2, sizeof(arg2)-1, "%d", pid);
    gdbserver_args[sizeof(gdbserver_args)/sizeof(gdbserver_args[0])-3] = arg1;
    gdbserver_args[sizeof(gdbserver_args)/sizeof(gdbserver_args[0])-2] = arg2;

    if(gdbserver_pid != -1)
    {
        kill(gdbserver_pid, SIGTERM);
        CHECK(waitpid(gdbserver_pid, NULL, 0) == gdbserver_pid);
        gdbserver_pid = -1;
    }
    if(strace_pid != -1)
    {
        kill(strace_pid, SIGTERM);
        CHECK(waitpid(strace_pid, NULL, 0) == strace_pid);
        strace_pid = -1;
    }

    CHECK((gdbserver_pid = fork()) != -1);

    if(gdbserver_pid == 0)
    {
        CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) != -1);

        CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != -1);

        CHECK(dup2(gdbserver_pipe[1], STDERR_FILENO) != -1);

        close_fd();

        if (execvp(gdbserver_args[0], gdbserver_args) == -1)
        {
            if (errno == ENOENT)
            {
                fprintf(stderr, "ERROR: \"%s\" cannot be found in PATH!\n", gdbserver_args[0]);
            }
            else if (errno == EACCES)
            {
                fprintf(stderr, "ERROR: \"%s\" does not have execution privileges!\n", gdbserver_args[0]);
            }
            else
            {
                fprintf(stderr, "ERROR: %s  %s:%d\n", strerror(errno), __FILE__, __LINE__);
            }
        }

        exit(EXIT_FAILURE);
    }

    info_printf("Gdbserver start, pid=%d\n", gdbserver_pid);

    // Wait for gdbserver
    run = 1;
    while(run)
    {
        memset(buf, 0, sizeof(buf));
        CHECK(read(gdbserver_pipe[0], buf, sizeof(buf)-1) >= 0);
        if(strstr(buf, "Listening on port"))
        {
            result = 1;
            run = 0;
        }
        else if(strstr(buf, "Exiting"))
        {
            result = 0;
            run = 0;
        }
        else if(strstr(buf, "info or a printed manual"))
        {
            result = 0;
            run = 0;
        }
        else if (strstr(buf, "ERROR"))
        {
            result = 0;
            run = 0;
        }
        gdbserver_output(buf);
    }

    if(arg_opt_s && stopped)
    {
        CHECK(kill(pid, SIGCONT) != -1);
        stopped = 0;
    }

    return result;
}

int strace_attach_pid(int pid)
{
    char arg1[0x100];
    char buf[0x100];
    
    memset(arg1, 0, sizeof(arg1));
    snprintf(arg1, sizeof(arg1)-1, "%d", pid);
    strace_args[sizeof(strace_args)/sizeof(strace_args[0])-2] = arg1;

    if(gdbserver_pid != -1)
    {
        kill(gdbserver_pid, SIGTERM);
        waitpid(gdbserver_pid, NULL, 0);
        gdbserver_pid = -1;
    }
    if(strace_pid != -1)
    {
        kill(strace_pid, SIGTERM);
        waitpid(strace_pid, NULL, 0);
        strace_pid = -1;
    }

    CHECK((strace_pid = fork()) != -1);

    if(strace_pid == 0)
    {
        CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) != -1);

        CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != -1);

        CHECK(dup2(strace_pipe[1], STDERR_FILENO) != -1);

        close_fd();
        
        if (execvp(strace_args[0], strace_args) == -1)
        {
            if (errno == ENOENT)
            {
                fprintf(stderr, "ERROR: \"%s\" cannot be found in PATH!\n", strace_args[0]);
            }
            else if (errno == EACCES)
            {
                fprintf(stderr, "ERROR: \"%s\" does not have execution privileges!\n", strace_args[0]);
            }
            else
            {
                fprintf(stderr, "ERROR: %s  %s:%d\n", strerror(errno), __FILE__, __LINE__);
            }
        }

        exit(EXIT_FAILURE);
    }

    info_printf("Strace start, pid=%d\n", strace_pid);

    memset(buf, 0, sizeof(buf));
    CHECK(read(strace_pipe[0], buf, sizeof(buf)-1) > 0);
    strace_output(buf);

    if(arg_opt_s && stopped)
    {
        CHECK(kill(pid, SIGCONT) != -1);
        stopped = 0;
    }

    return 1;
}