// gcc -static -g debug-server.c -o debug-server
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
#include <sys/prctl.h>

char *service_args[]    = {"/bin/sh", NULL};
char *gdbserver_args[]  = {"/usr/bin/gdbserver", "--attach", /* Reserved parameter */ NULL, NULL, NULL};
char *strace_args[]     = {"/usr/bin/strace", "-f", "-p", /* Reserved parameter */ NULL, NULL};

#define SERVICE_PORT    9541
#define COMMAND_PORT    9545
#define GDB_PORT        9549

int ser_pid         = -1; // Service PID
int gdb_pid         = -1; // gdbserver PID
int strace_pid      = -1; // strace PID

int service_sock    = -1;
int command_sock    = -1;
int sfd             = -1;
int epollfd         = -1;

struct sockaddr_in gdb_client_addr = {0};
int existed_pid = -1;
sigset_t old_mask;
int gdb_pipe[2] = {-1, -1};
int strace_pipe[2] = {-1, -1};
int tty = 0;

#define COMMAND_GDB_REGISTER        0x01
#define COMMAND_GDBSERVER_ATTACH    0x02
#define COMMAND_STRACE_ATTACH       0x03
#define COMMAND_GET_ADDRESS         0x04

#define OK_GREEN        "\033[92m"
#define WARNING_YELLOW  "\033[93m"
#define FAIL_RED        "\033[91m"
#define END_CLEAN       "\033[0m"
#define GDB_COLOR       "\033[96m"
#define STRACE_COLOR    "\033[95m"

int log_output(char *level, char *color, char *msg)
{
    char time_buf[0x100];
    time_t now;
    struct tm *now_tm;
    if(tty)
    {
        now = time(NULL);
        now_tm = localtime(&now);
        memset(time_buf, 0, sizeof(time_buf));
        strftime(time_buf, sizeof(time_buf) - 1, "%Y-%m-%d %H:%M:%S", now_tm);
        return fprintf(stdout, "%s%s | %-7s | %s" END_CLEAN, color, time_buf, level, msg);
    }
    else
    {
        return fprintf(stdout, "%s | %-7s | %s", time_buf, level, msg);
    }
    return 0;
}

int info(char *msg)
{
    return log_output("INFO", OK_GREEN, msg);
}

int warning(char *msg)
{
    return log_output("WARNING", WARNING_YELLOW, msg);
}

int error(char *msg)
{
    return log_output("ERROR", FAIL_RED, msg);
}

int gdb_output(char *msg)
{
    char buf[0x100];
    char *ptr = NULL;
    int result = 0;

    ptr = strtok(msg, "\n");
    while(ptr != NULL)
    {
        memset(buf, 0, sizeof(buf));
        strncat(buf, ptr, sizeof(buf)-1);
        strncat(buf, "\n", sizeof(buf)-1);
        result += log_output("GDB", GDB_COLOR, buf);
        ptr = strtok(NULL, "\n");
    }

    return result;
}

int strace_output(char *msg)
{
    if(tty)
    {
        return fprintf(stdout, STRACE_COLOR "%s" END_CLEAN, msg);
    }
    else
    {
        return fprintf(stdout, "%s", msg);
    }
}

int pre_perror(char *msg)
{
    char buf[0x100];
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf)-1, "%s: %m\n", msg);
    return error(buf);
}

int info_printf(const char* format, ...)
{
    char buf[0x100];
    va_list arglist;

    memset(buf, 0, sizeof(buf));
    va_start(arglist, format);
    vsnprintf(buf, sizeof(buf)-1, format, arglist);
    va_end(arglist);
    return info(buf);
}

int warning_printf(const char* format, ...)
{
    char buf[0x100];
    va_list arglist;

    memset(buf, 0, sizeof(buf));
    va_start(arglist, format);
    vsnprintf(buf, sizeof(buf)-1, format, arglist);
    va_end(arglist);
    return warning(buf);
}

int error_printf(const char* format, ...)
{
    char buf[0x100];
    va_list arglist;

    memset(buf, 0, sizeof(buf));
    va_start(arglist, format);
    vsnprintf(buf, sizeof(buf)-1, format, arglist);
    va_end(arglist);
    return error(buf);
}

int init_command_service()
{
    struct sockaddr_in server_addr;
    int nOptval;

    command_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (command_sock == -1) {
        pre_perror("socket");
        exit(1);
    }

    // Don't wait WAIT signal.
    nOptval = 1;
    if (setsockopt(command_sock, SOL_SOCKET, SO_REUSEADDR, &nOptval, sizeof(int)) < 0)
    {
        pre_perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(COMMAND_PORT);

    // Bind the socket to the server address
    if (bind(command_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        pre_perror("bind");
        exit(1);
    }
    return 0;
}

int init_service()
{
    struct sockaddr_in server_addr;
    int nOptval;

    service_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (service_sock == -1) {
        pre_perror("socket");
        exit(1);
    }

    // Don't wait WAIT signal.
    nOptval = 1;
    if (setsockopt(service_sock, SOL_SOCKET, SO_REUSEADDR, &nOptval, sizeof(int)) < 0)
    {
        pre_perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(SERVICE_PORT);

    // Bind the socket to the server address
    if (bind(service_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        pre_perror("bind");
        exit(1);
    }

    listen(service_sock, 256);

    return 0;
}

int set_sig_hander()
{
    sigset_t new_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGINT);
    sigaddset(&new_mask, SIGQUIT);
    sigaddset(&new_mask, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1 || (sfd = signalfd(-1, &new_mask, 0)) == -1)
    {
        pre_perror("sigprocmask or signalfd");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int monitor_fd(int fd)
{
    struct epoll_event event;

    event.events = EPOLLIN;
	event.data.fd = fd;

    if(epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1)
    {
        pre_perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }

    return 0;
}

int gdb_attach_pid(int pid)
{
    char arg1[0x100], arg2[0x100];
    char buf[0x100];
    int run = 0;
    
    memset(arg1, 0, sizeof(arg1));
    memset(arg2, 0, sizeof(arg2));
    snprintf(arg1, sizeof(arg1)-1, "*:%d", GDB_PORT);
    snprintf(arg2, sizeof(arg2)-1, "%d", pid);
    gdbserver_args[sizeof(strace_args)/sizeof(strace_args[0])-3] = arg1;
    gdbserver_args[sizeof(strace_args)/sizeof(strace_args[0])-2] = arg2;

    if(gdb_pid != -1)
    {
        kill(gdb_pid, SIGTERM);
        waitpid(gdb_pid, NULL, 0);
        gdb_pid = -1;
    }
    if(strace_pid != -1)
    {
        kill(strace_pid, SIGTERM);
        waitpid(strace_pid, NULL, 0);
        strace_pid = -1;
    }

    gdb_pid = fork();
    if(gdb_pid == -1)
    {
        pre_perror("fork");
        exit(EXIT_FAILURE);
    }

    if(gdb_pid == 0)
    {
        dup2(gdb_pipe[1], STDERR_FILENO);
        if(epollfd != -1)           close(epollfd);
        if(command_sock != -1)      close(command_sock);
        if(service_sock != -1)      close(service_sock);
        if(sfd != -1)               close(sfd);
        if(gdb_pipe[0] != -1)       close(gdb_pipe[0]);
        if(gdb_pipe[1] != -1)       close(gdb_pipe[1]);
        if(strace_pipe[0] != -1)    close(strace_pipe[0]);
        if(strace_pipe[1] != -1)    close(strace_pipe[1]);
        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1)
        {
            pre_perror("sigprocmask");
            exit(EXIT_FAILURE);
        }
        if(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1)
        {
            pre_perror("prctl:PR_SET_PDEATHSIG");
            exit(EXIT_FAILURE);
        }
        execvp(gdbserver_args[0], gdbserver_args);
        exit(EXIT_FAILURE);
    }

    // Wait for gdbserver
    run = 1;
    while(run)
    {
        memset(buf, 0, sizeof(buf));
        read(gdb_pipe[0], buf, sizeof(buf)-1);
        run = strstr(buf, "Listening on port") == NULL && strstr(buf, "Exiting") == NULL;
        gdb_output(buf);
    }

    return 1;
}

int strace_attach_pid(int pid)
{
    char arg1[0x100];
    char buf[0x100];
    
    memset(arg1, 0, sizeof(arg1));
    snprintf(arg1, sizeof(arg1)-1, "%d", pid);
    strace_args[sizeof(strace_args)/sizeof(strace_args[0])-2] = arg1;

    if(gdb_pid != -1)
    {
        kill(gdb_pid, SIGTERM);
        waitpid(gdb_pid, NULL, 0);
        gdb_pid = -1;
    }
    if(strace_pid != -1)
    {
        kill(strace_pid, SIGTERM);
        waitpid(strace_pid, NULL, 0);
        strace_pid = -1;
    }

    strace_pid = fork();
    if(strace_pid == -1)
    {
        pre_perror("fork");
        exit(EXIT_FAILURE);
    }

    if(strace_pid == 0)
    {
        dup2(strace_pipe[1], STDERR_FILENO);
        if(epollfd != -1)           close(epollfd);
        if(command_sock != -1)      close(command_sock);
        if(service_sock != -1)      close(service_sock);
        if(sfd != -1)               close(sfd);
        if(gdb_pipe[0] != -1)       close(gdb_pipe[0]);
        if(gdb_pipe[1] != -1)       close(gdb_pipe[1]);
        if(strace_pipe[0] != -1)    close(strace_pipe[0]);
        if(strace_pipe[1] != -1)    close(strace_pipe[1]);
        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1)
        {
            pre_perror("sigprocmask");
            exit(EXIT_FAILURE);
        }
        if(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1)
        {
            pre_perror("prctl:PR_SET_PDEATHSIG");
            exit(EXIT_FAILURE);
        }
        execvp(strace_args[0], strace_args);
        exit(EXIT_FAILURE);
    }

    memset(buf, 0, sizeof(buf));
    read(strace_pipe[0], buf, sizeof(buf)-1);
    strace_output(buf);

    return 1;
}

size_t get_address(int pid, char *search)
{
    char buf[0x100];
    char buf2[0x1000];
    int fd;
    size_t result = 0;
    int i;
    char chr;
    int eof = 0;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf)-1, "/proc/%d/maps", pid);
    fd = open(buf, O_RDONLY);
    if(fd != -1)
    {
        for(eof = 0; eof != 1;)
        {
            memset(buf2, 0, sizeof(buf2));
            for(i = 0; eof != 1 && i < sizeof(buf2) - 1; i++)
            {
                if(read(fd, &chr, sizeof(chr)) != 1)
                {
                    eof = 1;
                }

                buf2[i] = chr;

                if(chr == '\n' || chr == '\0')
                {
                    buf2[i] = '\0';
                    break;
                }
            }

            if(strstr(buf2, search))
            {
                for(i = 0; i < sizeof(buf2) && buf2[i] && buf2[i] != '-'; i++)
                {
                    if(buf2[i] >= '0' && buf2[i] <= '9')
                    {
                        result = (result << 4) + (buf2[i] - '0');
                    }
                    else if(buf2[i] >= 'a' && buf2[i] <= 'f')
                    {
                        result = (result << 4) + (buf2[i] - 'a' + 10);
                    }
                }
                break;
            }
        }
        close(fd);
    }
    return result;
}

int command_handler()
{
    char buf[0x100];
    socklen_t client_addr_size;
    struct sockaddr_in client_addr;
    int recv_len;
    unsigned char command, path_len;
    size_t addr = 0;

    client_addr_size = sizeof(client_addr);
    memset(buf, 0, sizeof(buf));
    recv_len = recvfrom(command_sock, buf, sizeof(buf)-1, 0, (struct sockaddr *)&client_addr, &client_addr_size);

    command = buf[0];
    switch(command)
    {
    case COMMAND_GDB_REGISTER:
        memcpy(&gdb_client_addr, &client_addr, sizeof(gdb_client_addr));
        info_printf("%s gdb client registered.\n", inet_ntoa(client_addr.sin_addr));

        client_addr_size = sizeof(client_addr);
        if (sendto(command_sock, buf, recv_len, 0, (struct sockaddr *)&client_addr, client_addr_size) == -1) {
            pre_perror("sendto");
            exit(EXIT_FAILURE);
        }
        break;
    case COMMAND_GDBSERVER_ATTACH:
        if(gdb_client_addr.sin_addr.s_addr)
        {
            if(ser_pid != -1)
            {
                gdb_attach_pid(ser_pid);
            }
            else if(existed_pid != -1)
            {
                gdb_attach_pid(existed_pid);
            }
            client_addr_size = sizeof(gdb_client_addr);
            // Send the received data back to the two client
            if (sendto(command_sock, buf, recv_len, 0, (struct sockaddr *)&gdb_client_addr, client_addr_size) == -1) {
                pre_perror("sendto");
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            warning("There is no gdb client\n");
        }
        
        client_addr_size = sizeof(client_addr);
        if (sendto(command_sock, buf, recv_len, 0, (struct sockaddr *)&client_addr, client_addr_size) == -1) {
            pre_perror("sendto");
            exit(EXIT_FAILURE);
        }
        break;
    case COMMAND_STRACE_ATTACH:
        if(ser_pid != -1)
        {
            strace_attach_pid(ser_pid);
            
        }
        else if(existed_pid != -1)
        {
            strace_attach_pid(existed_pid);
        }

        client_addr_size = sizeof(client_addr);
        if (sendto(command_sock, buf, recv_len, 0, (struct sockaddr *)&client_addr, client_addr_size) == -1) {
            pre_perror("sendto");
            exit(EXIT_FAILURE);
        }
        break;
    case COMMAND_GET_ADDRESS:
        addr = 0;
        if(ser_pid != -1)
        {
            addr = get_address(ser_pid, buf + 2);
        }
        else if(existed_pid != -1)
        {
            addr = get_address(existed_pid, buf + 2);
        }

        memset(buf, 0, sizeof(buf));
        buf[0] = COMMAND_GET_ADDRESS;
        buf[1] = sizeof(addr);
        *(size_t*)&buf[2] = addr;
        client_addr_size = sizeof(client_addr);
        if (sendto(command_sock, buf, 2 + sizeof(addr), 0, (struct sockaddr *)&client_addr, client_addr_size) == -1) {
            pre_perror("sendto");
            exit(EXIT_FAILURE);
        }
        break;
    default:
        warning_printf("Unknown command 0x%02X\n", command);
        break;
    }

    return 1;
}

int service_handler()
{
    int client_sock = -1;
    socklen_t client_addr_size;
    struct sockaddr_in client_addr;

    client_addr_size = sizeof(client_addr);
    client_sock = accept(service_sock, (struct sockaddr *)&client_addr, &client_addr_size);
    if(client_sock == -1)
    {
        pre_perror("accept");
        exit(EXIT_FAILURE);
    }
    ser_pid = fork();
    if(ser_pid == -1)
    {
        pre_perror("fork");
        exit(EXIT_FAILURE);
    }

    if(ser_pid == 0)
    {
        dup2(client_sock, STDIN_FILENO);
        dup2(client_sock, STDOUT_FILENO);
        dup2(client_sock, STDERR_FILENO);
        if(epollfd != -1)       close(epollfd);
        if(command_sock != -1)  close(command_sock);
        if(service_sock != -1)  close(service_sock);
        if(sfd != -1)           close(sfd);
        if(client_sock != -1)   close(client_sock);
        if(gdb_pipe[0] != -1)   close(gdb_pipe[0]);
        if(gdb_pipe[1] != -1)   close(gdb_pipe[1]);
        if (sigprocmask(SIG_SETMASK, &old_mask, NULL) == -1)
        {
            pre_perror("sigprocmask");
            exit(EXIT_FAILURE);
        }
        if(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == -1)
        {
            pre_perror("prctl:PR_SET_PDEATHSIG");
            exit(EXIT_FAILURE);
        }
        prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
        execvp(service_args[0], service_args);
        exit(EXIT_FAILURE);
    }

    if(client_sock != -1) close(client_sock);
    info_printf("Service %d start\n", ser_pid);

    return 1;
}

int signal_hander()
{
    pid_t pid;
    struct signalfd_siginfo fdsi;
    int result;
    int ret_val = 1;
    int wstatus;

    result = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
    if(result == sizeof(struct signalfd_siginfo))
    {
        switch (fdsi.ssi_signo)
        {
        case SIGINT:
            ret_val = 0;
            info("Receive signal SIGINT\n");
            break;
        
        case SIGQUIT:
            ret_val = 0;
            info("Receive signal SIGQUIT\n");
            break;

        case SIGTERM:
            ret_val = 0;
            info("Receive signal SIGTERM\n");
            break;

        case SIGCHLD:
            ret_val = 1;
            while(1)
            {
                pid = waitpid(0, &wstatus, WNOHANG);
                if(pid == 0 || pid == -1)
                {
                    break;
                }
                if (WIFEXITED(wstatus)) {
                    info_printf("Pid %d exited, status=%d\n", pid, WEXITSTATUS(wstatus));
                } else if (WIFSIGNALED(wstatus)) {
                    info_printf("Pid %d killed by signal %d\n", pid, WTERMSIG(wstatus));
                } else if (WIFSTOPPED(wstatus)) {
                    info_printf("Pid %d stopped by signal %d\n", pid, WSTOPSIG(wstatus));
                } else if (WIFCONTINUED(wstatus)) {
                    info_printf("Pid %d continued\n", pid);
                }
                if      (pid == ser_pid)        ser_pid     = -1;
                else if (pid == gdb_pid)        gdb_pid     = -1;
                else if (pid == strace_pid)     strace_pid  = -1;
                else if (pid == existed_pid)    existed_pid = -1;
            }
            break;
        
        default:
            warning_printf("Read unexpected signal %d\n", fdsi.ssi_signo);
            break;
        }
    }
    else
    {
        pre_perror("read");
        exit(EXIT_FAILURE);
    }

    return ret_val;
}

int gdb_pipe_hander()
{
    char buf[0x100];
    memset(buf, 0, sizeof(buf));
    read(gdb_pipe[0], buf, sizeof(buf)-1);
    gdb_output(buf);
    return 1;
}

int strace_pipe_hander()
{
    char buf[0x100];
    memset(buf, 0, sizeof(buf));
    read(strace_pipe[0], buf, sizeof(buf)-1);
    strace_output(buf);
    return 1;
}

int main(int argc, char **args)
{
    struct epoll_event events[0x10];
    int event_num;
    int run;
    int i;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    if(argc > 1)
    {
        existed_pid = atoi(args[1]);
    }
    else
    {
        if(access(service_args[0], X_OK) == -1)
        {
            fprintf(stderr, "'%s' is not executable!\n", service_args[0]);
            exit(EXIT_FAILURE);
        }
    }

    tty = isatty(STDOUT_FILENO);

    if(pipe(gdb_pipe) == -1)
    {
        pre_perror("pipe");
        exit(EXIT_FAILURE);
    }

    if(pipe(strace_pipe) == -1)
    {
        pre_perror("pipe");
        exit(EXIT_FAILURE);
    }

    epollfd = epoll_create(6);
    if (epollfd == -1) {
        pre_perror("epoll_create");
        exit(EXIT_FAILURE);
    }


    init_command_service();
    if(existed_pid == -1)
    {
        init_service();
    }
    set_sig_hander();

    monitor_fd(command_sock);
    if(existed_pid == -1)
    {
        monitor_fd(service_sock);
    }
    monitor_fd(sfd);
    monitor_fd(gdb_pipe[0]);
    monitor_fd(strace_pipe[0]);

    info("Start service\n");
    run = 1;
    while(run)
    {
        event_num = epoll_wait(epollfd, events, sizeof(events)/sizeof(events[0]), -1);
        for(i = 0; i < event_num; i++)
        {
            if(events[i].data.fd == command_sock)
            {
                run = command_handler();
            }
            else if(existed_pid == -1 && events[i].data.fd == service_sock)
            {
                run = service_handler();
            }
            else if(events[i].data.fd == sfd)
            {
                run = signal_hander();
            }
            else if(events[i].data.fd == gdb_pipe[0])
            {
                run = gdb_pipe_hander();
            }
            else if(events[i].data.fd == strace_pipe[0])
            {
                run = strace_pipe_hander();
            }
        }
    }
    info("Exit service\n");

    return 0;
}
