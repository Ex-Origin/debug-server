#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include "handler.h"
#include "fd.h"
#include "pid.h"
#include "log.h"

char *sig_name[] = {
    "0",
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "7",
    "SIGFPE",
    "SIGKILL",
    "SIGBUS",
    "SIGSEGV",
    "SIGSYS",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
    "SIGURG",
    "SIGSTOP",
    "SIGTSTP",
    "SIGCONT",
    "SIGCHLD",
    "SIGTTIN",
    "SIGTTOU",
    "SIGPOLL",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGVTALRM",
    "SIGPROF",
    "SIGWINCH",
    "29",
    "SIGUSR1",
    "SIGUSR2",
    "__SIGRTMIN"
};

int child_signal_handler()
{
    int pid = 0, status = 0;
    int i, is_con = 0, index;
    time_t spend;
    char signal_buf[0x100];

    while(1)
    {
        pid = waitpid(-1, &status, WNOHANG);
        if(pid == 0 || pid == -1)
        {
            break;
        }

        if (WIFEXITED(status))
        {
            if (pid == service_pid)
            {
                info_printf("Service exited, pid=%d, status=%d\n", pid, WEXITSTATUS(status));
                service_pid = -1;
            }
            else if (pid == gdbserver_pid)
            {
                info_printf("Gdbserver exited, pid=%d, status=%d\n", pid, WEXITSTATUS(status));
                gdbserver_pid = -1;
            }
            else if (pid == strace_pid)
            {
                info_printf("Strace exited, pid=%d, status=%d\n", pid, WEXITSTATUS(status));
                strace_pid  = -1;
            }
            else
            {
                info_printf("Unknown child process exited, pid=%d, status=%d\n", pid, WEXITSTATUS(status));
            }
        }
        else if (WIFSIGNALED(status))
        {
            memset(signal_buf, 0, sizeof(signal_buf));
            if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*))
            {
                strncpy(signal_buf, sig_name[WTERMSIG(status)], sizeof(signal_buf)-1);
            }
            else
            {
                snprintf(signal_buf, sizeof(signal_buf)-1, "%d", WTERMSIG(status));
            }

            if (pid == service_pid)
            {
                info_printf("Service killed, pid=%d, signal=%s\n", pid, signal_buf);
                service_pid = -1;
            }
            else if (pid == gdbserver_pid)
            {
                info_printf("Gdbserver killed, pid=%d, signal=%s\n", pid, signal_buf);
                gdbserver_pid = -1;
            }
            else if (pid == strace_pid)
            {
                info_printf("Strace killed, pid=%d, signal=%s\n", pid, signal_buf);
                strace_pid  = -1;
            }
            else
            {
                info_printf("Unknown child process killed, pid=%d, signal=%s\n", pid, signal_buf);
            }
        }
        else if (WIFSTOPPED(status))
        {
            if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*))
            {
                info_printf("Pid %d stopped by signal %s\n", pid, sig_name[WSTOPSIG(status)]);
            }
            else
            {
                info_printf("Pid %d stopped by signal %d\n", pid, WSTOPSIG(status));
            }
        }
        else if (WIFCONTINUED(status))
        {
            info_printf("Pid %d continued\n", pid);
        }
    }

    return 0;
}

int signal_handler()
{
    pid_t pid;
    struct signalfd_siginfo fdsi;
    int result;
    int ret_val = 1;
    int wstatus;

    CHECK((result = read(signal_fd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
    if(result == sizeof(struct signalfd_siginfo))
    {
        switch (fdsi.ssi_signo)
        {
        case SIGINT:
            ret_val = 0;
            info_printf("Receive signal SIGINT\n");
            break;
        
        case SIGQUIT:
            ret_val = 0;
            info_printf("Receive signal SIGQUIT\n");
            break;

        case SIGTERM:
            ret_val = 0;
            info_printf("Receive signal SIGTERM\n");
            break;

        case SIGCHLD:
            ret_val = 1;
            child_signal_handler();
            break;
        
        default:
            warning_printf("Read unexpected signal %d\n", fdsi.ssi_signo);
            break;
        }
    }

    return ret_val;
}