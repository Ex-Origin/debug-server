#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include "debug-server.h"

int stopped = 0;

int close_fd()
{
    if(epoll_fd != -1)
    {
        CHECK(close(epoll_fd) != -1);
    }
    if(command_socket != -1)
    {
        CHECK(close(command_socket) != -1);
    }
    if(service_socket != -1)
    {
        CHECK(close(service_socket) != -1);
    }
    if(signal_fd != -1)
    {
        CHECK(close(signal_fd) != -1);
    }
    if(gdbserver_pipe[0] != -1)
    {
        CHECK(close(gdbserver_pipe[0]) != -1);
    }
    if(gdbserver_pipe[1] != -1)
    {
        CHECK(close(gdbserver_pipe[1]) != -1);
    }
    if(strace_pipe[0] != -1)
    {
        CHECK(close(strace_pipe[0]) != -1);
    }
    if(strace_pipe[1] != -1)
    {
        CHECK(close(strace_pipe[1]) != -1);
    }

    return 0;
}

int ptrace_for_stopping_at_entry_point(pid_t pid)
{
    struct signalfd_siginfo fdsi;
    int result;
    int wstatus;
    pid_t tmp_pid;

    CHECK(ptrace(PTRACE_ATTACH, pid, NULL, 0, 0, 0) != -1);

    for(tmp_pid = -1; tmp_pid != pid;)
    {
        if(tmp_pid == -1)
        {
            CHECK((result = read(signal_fd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
            CHECK(fdsi.ssi_signo == SIGCHLD);
        }
        tmp_pid = waitpid(pid, &wstatus, 0);
    }
    CHECK((wstatus >> 16) == 0);
    debug_printf("Tracee(%d) is ready.\n", pid);

    CHECK(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL, 0, 0) != -1);
    CHECK(ptrace(PTRACE_CONT, pid, NULL, 0, 0, 0) != -1);
    CHECK((result = read(signal_fd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
    CHECK(fdsi.ssi_signo == SIGCHLD);
    CHECK(fdsi.ssi_pid == pid);
    CHECK(waitpid(pid, &wstatus, 0) == pid);
    CHECK((wstatus >> 16) == 0);
    debug_printf("Continue %d.\n", pid);

    CHECK(ptrace(PTRACE_CONT, pid, NULL, 0, 0, 0) != -1);
    CHECK((result = read(signal_fd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
    CHECK(fdsi.ssi_signo == SIGCHLD);
    CHECK(fdsi.ssi_pid == pid);
    CHECK(waitpid(pid, &wstatus, 0) == pid);
    CHECK(WIFSTOPPED(wstatus));
    CHECK(WSTOPSIG(wstatus) == SIGTRAP);
    CHECK((wstatus >> 16) == PTRACE_EVENT_EXEC);
    debug_printf("Receive a PTRACE_EVENT_EXEC event from %d.\n", pid);

    CHECK(kill(pid, SIGSTOP) != -1);
    CHECK(ptrace(PTRACE_DETACH, pid, NULL, 0, 0, 0) != -1);
    CHECK((result = read(signal_fd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
    CHECK(fdsi.ssi_signo == SIGCHLD);
    CHECK(fdsi.ssi_pid == pid);

    return 0;
}

int start_service(int client_sock)
{
    struct rlimit limit;

    if(!arg_opt_m && service_pid != -1)
    {
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

        kill(service_pid, SIGKILL);
        CHECK(waitpid(service_pid, NULL, 0) == service_pid);
        service_pid = -1;
    }
    
    service_pid = fork();
    if(service_pid == -1)
    {
        warning_printf("fork error  %s:%d\n", __FILE__, __LINE__);
    }
    else if(service_pid == 0)
    {
        if(arg_opt_u == 0)
        {
            limit.rlim_cur = 0x100000000;
            limit.rlim_max = 0x100000000;
            CHECK(setrlimit(RLIMIT_AS, &limit) != -1);
        }

        CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) != -1);

        CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != -1);

        if(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) == -1)
        {
            warning_printf("prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) failed\n");
        }

        if(client_sock > 0)
        {
            CHECK(dup2(client_sock, STDIN_FILENO) != -1);
            CHECK(close(client_sock) != -1);
        }

        close_fd();

        CHECK(setsid() != -1);

        if(arg_opt_n)
        {
            CHECK(personality(ADDR_NO_RANDOMIZE) != -1);
        }

        if(arg_opt_s)
        {
            CHECK(kill(0, SIGSTOP) != -1);
        }

        if(client_sock > 0)
        {
            dup2(STDIN_FILENO, STDOUT_FILENO);
            dup2(STDIN_FILENO, STDERR_FILENO);
        }
        
        if (execvp(arg_execve_argv[0], arg_execve_argv) == -1)
        {
            if (errno == ENOENT)
            {
                if (strstr(arg_execve_argv[0], "/"))
                {
                    fprintf(stderr, "ERROR: \"%s\" does not exist!\n", arg_execve_argv[0], arg_execve_argv[0]);
                }
                else
                {
                    fprintf(stderr, "ERROR: \"%s\" cannot be found in PATH. Perhaps try running \"./%s\"!\n", arg_execve_argv[0], arg_execve_argv[0]);
                }
            }
            else if (errno == EACCES)
            {
                fprintf(stderr, "ERROR: \"%s\" does not have execution privileges!\n", arg_execve_argv[0]);
            }
            else
            {
                fprintf(stderr, "ERROR: %s  %s:%d\n", strerror(errno), __FILE__, __LINE__);
            }
        }
        exit(EXIT_FAILURE);
    }
    else
    {
        if(arg_opt_s)
        {
            ptrace_for_stopping_at_entry_point(service_pid);
            stopped = 1;
        }

        info_printf("Service start, pid=%d\n", service_pid);
    }

    return 0;
}

int service_handler()
{
    int client_sock = -1;
    socklen_t client_addr_size;
    struct sockaddr_in6 client_addr;
    char clientIP[INET6_ADDRSTRLEN], ip_buf[0x100];
    int clientPort;

    client_addr_size = sizeof(client_addr);
    CHECK((client_sock = accept(service_socket, (struct sockaddr *)&client_addr, &client_addr_size)) != -1);
    // Get the client's IP address and port
    memset(clientIP, 0, sizeof(clientIP));
    inet_ntop(AF_INET6, &(client_addr.sin6_addr), clientIP, INET6_ADDRSTRLEN);
    memset(ip_buf, 0, sizeof(ip_buf));
    if (clientIP[0] == ':')
    {
        snprintf(ip_buf, sizeof(ip_buf)-1, "%s", clientIP + 7);
    }
    else
    {
        snprintf(ip_buf, sizeof(ip_buf)-1, "[%s]", clientIP);
    }
    clientPort = ntohs(client_addr.sin6_port);

    debug_printf("Receive %s:%d from service_sock\n", ip_buf, clientPort);

    start_service(client_sock);

    if(client_sock != -1)
    {
        CHECK(close(client_sock) != -1);
    }

    return 1;
}