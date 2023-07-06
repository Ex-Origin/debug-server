/**
 * Compile:     gcc -static -g debug-server.c -o debug-server
 * Repository:  https://github.com/Ex-Origin/debug-server
*/
#define _GNU_SOURCE
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
#include <sys/ptrace.h>
#include <sys/personality.h>

char *service_args[]    = {"/bin/sh", NULL};
char *gdbserver_args[]  = {"/usr/bin/gdbserver", "--attach", /* Reserved parameter */ NULL, NULL, NULL};
char *strace_args[]     = {"/usr/bin/strace", "-f", "-p", /* Reserved parameter */ NULL, NULL};
// #define HALT_AT_ENTRY_POINT

#define SERVICE_PORT    9541
#define COMMAND_PORT    9545
#define GDB_PORT        9549

#define VERSION         "1.1.1"

int ser_pid         = -1; // Service PID
int gdb_pid         = -1; // gdbserver PID
int strace_pid      = -1; // strace PID

int service_sock    = -1;
int command_sock    = -1;
int sfd             = -1;
int epollfd         = -1;

struct sockaddr_in6 gdb_client_addr = {0};
char *popen_arg = NULL;
sigset_t old_mask;
int gdb_pipe[2] = {-1, -1};
int strace_pipe[2] = {-1, -1};
int tty = 0;

#define COMMAND_GDB_REGISTER        0x01
#define COMMAND_GDBSERVER_ATTACH    0x02
#define COMMAND_STRACE_ATTACH       0x03
#define COMMAND_GET_ADDRESS         0x04
#define COMMAND_GDB_LOGOUT          0x05

#define OK_GREEN        "\033[92m"
#define WARNING_YELLOW  "\033[93m"
#define FAIL_RED        "\033[91m"
#define END_CLEAN       "\033[0m"
#define GDB_COLOR       "\033[96m"
#define STRACE_COLOR    "\033[95m"

/**
 * The value must be TRUE, or the program will break down.
 * e.g., the value is thing what the program need to do.
 **/
#define CHECK(value)                                            \
    {                                                           \
        if ((value) == 0)                                       \
        {                                                       \
            error_printf("%m  %s:%d\n", __FILE__, __LINE__);    \
            abort();                                            \
        }                                                       \
    }

int prefix_printf(FILE* fp, char *level)
{
    va_list args;
    // variables to store the date and time components
    int hours, minutes, seconds, day, month, year;
    // `time_t` is an arithmetic time type
    time_t now = 0;
    // localtime converts a `time_t` value to calendar time and
    // returns a pointer to a `tm` structure with its members
    // filled with the corresponding values
    struct tm *local;
    size_t result;

    now = time(NULL);
#ifdef TIME_OFFSET
    now = now + (TIME_OFFSET);
#endif
    local = localtime(&now);

    hours = local->tm_hour;         // get hours since midnight (0-23)
    minutes = local->tm_min;        // get minutes passed after the hour (0-59)
    seconds = local->tm_sec;        // get seconds passed after a minute (0-59)
 
    day = local->tm_mday;            // get day of month (1 to 31)
    month = local->tm_mon + 1;      // get month of year (0 to 11)
    year = local->tm_year + 1900;   // get year since 1900

    result = fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d | %-7s | ", year, month, day, hours, minutes, seconds, level);

    return result;
}

#ifdef DEBUG
int debug_printf(const char *format, ...)
{
    va_list args;
    size_t result;

    prefix_printf(stdout, "DEBUG");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    return result;
}
#else
#define debug_printf(...)
#endif

int info_printf(const char *format, ...)
{
    va_list args;
    size_t result;

    if(tty)
    {
        fprintf(stderr, OK_GREEN);
    }
    prefix_printf(stdout, "INFO");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    if(tty)
    {
        fprintf(stderr, END_CLEAN);
    }

    return result;
}

int warning_printf(const char *format, ...)
{
    va_list args;
    size_t result;
    
    if(tty)
    {
        fprintf(stderr, WARNING_YELLOW);
    }
    prefix_printf(stdout, "WARNING");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    if(tty)
    {
        fprintf(stderr, END_CLEAN);
    }

    return result;
}

int error_printf(const char *format, ...)
{
    va_list args;
    size_t result;
    
    if(tty)
    {
        fprintf(stderr, FAIL_RED);
    }
    prefix_printf(stderr, "ERROR");
    va_start(args, format);
    result = vfprintf (stderr, format, args);
    va_end (args);
    if(tty)
    {
        fprintf(stderr, END_CLEAN);
    }

    return result;
}

int gdb_output(char *msg)
{
    char *ptr = NULL;
    int result = 0;

    if(tty)
    {
        fprintf(stdout, WARNING_YELLOW);
    }

    ptr = strtok(msg, "\n");
    while(ptr != NULL)
    {
        prefix_printf(stdout, "GDB");
        result += fprintf(stdout, "%s\n", ptr);
        ptr = strtok(NULL, "\n");
    }

    if(tty)
    {
        fprintf(stdout, END_CLEAN);
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

int init_socket()
{
    struct sockaddr_in6 server_addr;
    int nOptval;

    // Command socket
    CHECK((command_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) != -1);

    // Don't wait WAIT signal.
    nOptval = 1;
    CHECK(setsockopt(command_sock, SOL_SOCKET, SO_REUSEADDR, &nOptval, sizeof(int)) != -1);

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::", &server_addr.sin6_addr);
    server_addr.sin6_port = htons(COMMAND_PORT);

    // Bind the socket to the server address
    CHECK(bind(command_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != -1);

    if(popen_arg == NULL)
    {
        // Service socket
        CHECK((service_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) != -1);

        // Don't wait WAIT signal.
        nOptval = 1;
        CHECK(setsockopt(service_sock, SOL_SOCKET, SO_REUSEADDR, &nOptval, sizeof(int)) != -1);

        // Configure server address
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "::", &server_addr.sin6_addr);
        server_addr.sin6_port = htons(SERVICE_PORT);

        // Bind the socket to the server address
        CHECK(bind(service_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != -1);

        CHECK(listen(service_sock, 64) != -1);
    }

    return 0;
}

int set_sig_handler()
{
    sigset_t new_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGINT);
    sigaddset(&new_mask, SIGQUIT);
    sigaddset(&new_mask, SIGCHLD);

    CHECK(sigprocmask(SIG_BLOCK, &new_mask, &old_mask) != -1);

    CHECK((sfd = signalfd(-1, &new_mask, 0)) != -1);

    return 0;
}

int monitor_fd(int fd)
{
    struct epoll_event event;

    event.events = EPOLLIN;
	event.data.fd = fd;

    CHECK(epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) != -1);

    return 0;
}

int close_fd()
{
    if(epollfd != -1)
    {
        CHECK(close(epollfd) != -1);
    }
    if(command_sock != -1)
    {
        CHECK(close(command_sock) != -1);
    }
    if(service_sock != -1)
    {
        CHECK(close(service_sock) != -1);
    }
    if(sfd != -1)
    {
        CHECK(close(sfd) != -1);
    }
    if(gdb_pipe[0] != -1)
    {
        CHECK(close(gdb_pipe[0]) != -1);
    }
    if(gdb_pipe[1] != -1)
    {
        CHECK(close(gdb_pipe[1]) != -1);
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

int gdb_attach_pid(int pid)
{
    char arg1[0x100], arg2[0x100];
    char buf[0x100];
    int run = 0;
    
    memset(arg1, 0, sizeof(arg1));
    memset(arg2, 0, sizeof(arg2));
    snprintf(arg1, sizeof(arg1)-1, ":::%d", GDB_PORT);
    snprintf(arg2, sizeof(arg2)-1, "%d", pid);
    gdbserver_args[sizeof(gdbserver_args)/sizeof(gdbserver_args[0])-3] = arg1;
    gdbserver_args[sizeof(gdbserver_args)/sizeof(gdbserver_args[0])-2] = arg2;

    if(gdb_pid != -1)
    {
        kill(gdb_pid, SIGTERM);
        CHECK(waitpid(gdb_pid, NULL, 0) == gdb_pid);
        gdb_pid = -1;
    }
    if(strace_pid != -1)
    {
        kill(strace_pid, SIGTERM);
        CHECK(waitpid(strace_pid, NULL, 0) == strace_pid);
        strace_pid = -1;
    }

    CHECK((gdb_pid = fork()) != -1);

    if(gdb_pid == 0)
    {
        CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) != -1);

        CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != -1);

        CHECK(dup2(gdb_pipe[1], STDERR_FILENO) != -1);

        close_fd();

        CHECK(execvp(gdbserver_args[0], gdbserver_args) != -1);

        exit(EXIT_FAILURE);
    }

    info_printf("Gdbserver start, pid=%d\n", gdb_pid);

    // Wait for gdbserver
    run = 1;
    while(run)
    {
        memset(buf, 0, sizeof(buf));
        CHECK(read(gdb_pipe[0], buf, sizeof(buf)-1) >= 0);
        run = strstr(buf, "Listening on port") == NULL && strstr(buf, "Exiting") == NULL;
        gdb_output(buf);
    }

#ifdef HALT_AT_ENTRY_POINT
    CHECK(kill(pid, SIGCONT) != -1);
#endif

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

    CHECK((strace_pid = fork()) != -1);

    if(strace_pid == 0)
    {
        CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) != -1);

        CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != -1);

        CHECK(dup2(strace_pipe[1], STDERR_FILENO) != -1);

        close_fd();
        
        CHECK(execvp(strace_args[0], strace_args) != -1);

        exit(EXIT_FAILURE);
    }

    info_printf("Strace start, pid=%d\n", strace_pid);

    memset(buf, 0, sizeof(buf));
    read(strace_pipe[0], buf, sizeof(buf)-1);
    strace_output(buf);

#ifdef HALT_AT_ENTRY_POINT
    CHECK(kill(pid, SIGCONT) != -1);
#endif

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
    struct sockaddr_in6 client_addr;
    int recv_len;
    unsigned char command, path_len;
    size_t addr = 0;
    char clientIP[INET6_ADDRSTRLEN], ip_buf[0x100];
    int clientPort;
    int pid;
    FILE *popen_fp = NULL;
    char popen_result[0x100];

    client_addr_size = sizeof(client_addr);
    memset(buf, 0, sizeof(buf));
    recv_len = recvfrom(command_sock, buf, sizeof(buf)-1, 0, (struct sockaddr *)&client_addr, &client_addr_size);

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

    debug_printf("Receive %s:%d from command_sock\n", ip_buf, clientPort);

    command = buf[0];
    switch(command)
    {
    case COMMAND_GDB_REGISTER:
        memcpy(&gdb_client_addr, &client_addr, sizeof(gdb_client_addr));
        info_printf("%s gdb client registered.\n", ip_buf);

        client_addr_size = sizeof(client_addr);
        
        CHECK(sendto(command_sock, buf, recv_len, 0, (struct sockaddr *)&client_addr, client_addr_size) != -1);

        break;
    case COMMAND_GDBSERVER_ATTACH:
        if(gdb_client_addr.sin6_family)
        {
            if(ser_pid != -1)
            {
                gdb_attach_pid(ser_pid);
            }
            else if(popen_arg != NULL)
            {
                CHECK((popen_fp = popen(popen_arg, "r")) != NULL);
                
                memset(popen_result, 0, sizeof(popen_result));
                CHECK(fread(popen_result, sizeof(popen_result[0]), sizeof(popen_result)-1, popen_fp) >= 0);
                
                CHECK(pclose(popen_fp) != -1);

                pid = atoi(popen_result);
                gdb_attach_pid(pid);
            }
            client_addr_size = sizeof(gdb_client_addr);
            // Send the received data back to the two client
            CHECK(sendto(command_sock, buf, recv_len, 0, (struct sockaddr *)&gdb_client_addr, client_addr_size) != -1);
        }
        else
        {
            warning_printf("There is no gdb client\n");
        }
        
        client_addr_size = sizeof(client_addr);

        CHECK(sendto(command_sock, buf, recv_len, 0, (struct sockaddr *)&client_addr, client_addr_size) != -1);
        
        break;
    case COMMAND_STRACE_ATTACH:
        if(ser_pid != -1)
        {
            strace_attach_pid(ser_pid);
            
        }
        else if(popen_arg != NULL)
        {
            CHECK((popen_fp = popen(popen_arg, "r")) != NULL);
            
            memset(popen_result, 0, sizeof(popen_result));
            CHECK(fread(popen_result, sizeof(popen_result[0]), sizeof(popen_result)-1, popen_fp) >= 0);
            
            CHECK(pclose(popen_fp) != -1);

            pid = atoi(popen_result);
            strace_attach_pid(pid);
        }

        client_addr_size = sizeof(client_addr);

        CHECK(sendto(command_sock, buf, recv_len, 0, (struct sockaddr *)&client_addr, client_addr_size) != -1);
        
        break;
    case COMMAND_GET_ADDRESS:
        addr = 0;
        if(ser_pid != -1)
        {
            addr = get_address(ser_pid, buf + 2);
        }
        else if(popen_arg != NULL)
        {
            CHECK((popen_fp = popen(popen_arg, "r")) != NULL);
            
            memset(popen_result, 0, sizeof(popen_result));
            CHECK(fread(popen_result, sizeof(popen_result[0]), sizeof(popen_result)-1, popen_fp) >= 0);
            
            CHECK(pclose(popen_fp) != -1);

            pid = atoi(popen_result);
            addr = get_address(pid, buf + 2);
        }

        memset(buf, 0, sizeof(buf));
        buf[0] = COMMAND_GET_ADDRESS;
        buf[1] = sizeof(addr);
        *(size_t*)&buf[2] = addr;
        client_addr_size = sizeof(client_addr);

        CHECK(sendto(command_sock, buf, 2 + sizeof(addr), 0, (struct sockaddr *)&client_addr, client_addr_size) != -1);
        
        break;
    case COMMAND_GDB_LOGOUT:
        warning_printf("Receive COMMAND_GDB_LOGOUT from %s:%d\n", ip_buf, clientPort);
        break;
    default:
        warning_printf("Unknown command 0x%02X\n", command);
        break;
    }

    return 1;
}

#ifdef HALT_AT_ENTRY_POINT
int ptrace_for_stopping_at_entry_point(pid_t pid)
{
    struct signalfd_siginfo fdsi;
    int result;
    int wstatus;

    CHECK(ptrace(PTRACE_ATTACH, pid, NULL, 0, 0, 0) != -1);

    CHECK((result = read(sfd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
    CHECK(fdsi.ssi_signo == SIGCHLD);
    CHECK(fdsi.ssi_pid == pid);
    CHECK(waitpid(pid, &wstatus, WNOHANG) == pid);
    CHECK((wstatus >> 16) == 0);
    debug_printf("Tracee(%d) is ready.\n", pid);

    CHECK(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXEC, 0, 0) != -1);
    CHECK(ptrace(PTRACE_CONT, pid, NULL, 0, 0, 0) != -1);
    CHECK((result = read(sfd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
    CHECK(fdsi.ssi_signo == SIGCHLD);
    CHECK(fdsi.ssi_pid == pid);
    CHECK(waitpid(pid, &wstatus, WNOHANG) == pid);
    CHECK((wstatus >> 16) == 0);
    debug_printf("Continue %d.\n", pid);

    CHECK(ptrace(PTRACE_CONT, pid, NULL, 0, 0, 0) != -1);
    CHECK((result = read(sfd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
    CHECK(fdsi.ssi_signo == SIGCHLD);
    CHECK(fdsi.ssi_pid == pid);
    CHECK(waitpid(pid, &wstatus, WNOHANG) == pid);
    CHECK(WIFSTOPPED(wstatus));
    CHECK(WSTOPSIG(wstatus) == SIGTRAP);
    CHECK((wstatus >> 16) == PTRACE_EVENT_EXEC);
    debug_printf("Receive a PTRACE_EVENT_EXEC event from %d.\n", pid);

    CHECK(kill(pid, SIGSTOP) != -1);
    CHECK(ptrace(PTRACE_DETACH, pid, NULL, 0, 0, 0) != -1);
    CHECK((result = read(sfd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
    CHECK(fdsi.ssi_signo == SIGCHLD);
    CHECK(fdsi.ssi_pid == pid);
    CHECK(waitpid(pid, &wstatus, WNOHANG) == 0);

    return 0;
}
#endif

int service_handler()
{
    int client_sock = -1;
    socklen_t client_addr_size;
    struct sockaddr_in6 client_addr;
    char clientIP[INET6_ADDRSTRLEN], ip_buf[0x100];
    int clientPort;

    client_addr_size = sizeof(client_addr);
    CHECK((client_sock = accept(service_sock, (struct sockaddr *)&client_addr, &client_addr_size)) != -1);
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
    
    ser_pid = fork();
    if(ser_pid == -1)
    {
        warning_printf("fork error  %s:%d\n", __FILE__, __LINE__);
    }
    else if(ser_pid == 0)
    {
        CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) != -1);

        CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != -1);

        CHECK(prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) != -1);

        CHECK(dup2(client_sock, STDIN_FILENO) != -1);

        CHECK(close(client_sock) != -1);

        close_fd();

        CHECK(setsid() != -1);

#ifdef HALT_AT_ENTRY_POINT
        CHECK(personality(ADDR_NO_RANDOMIZE) != -1);
        CHECK(kill(0, SIGSTOP) != -1);
#endif

        dup2(STDIN_FILENO, STDOUT_FILENO);
        dup2(STDIN_FILENO, STDERR_FILENO);
        
        execvp(service_args[0], service_args);
        exit(EXIT_FAILURE);
    }
    else
    {
#ifdef HALT_AT_ENTRY_POINT
        ptrace_for_stopping_at_entry_point(ser_pid);
#endif

        info_printf("Service start, pid=%d\n", ser_pid);
    }

    if(client_sock != -1)
    {
        CHECK(close(client_sock) != -1);
    }

    return 1;
}

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
            if (pid == ser_pid)
            {
                info_printf("Service exited, pid=%d, status=%d\n", pid, WEXITSTATUS(status));
                ser_pid = -1;
            }
            else if (pid == gdb_pid)
            {
                info_printf("Gdbserver exited, pid=%d, status=%d\n", pid, WEXITSTATUS(status));
                gdb_pid = -1;
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

            if (pid == ser_pid)
            {
                info_printf("Service killed, pid=%d, signal=%s\n", pid, signal_buf);
                ser_pid = -1;
            }
            else if (pid == gdb_pid)
            {
                info_printf("Gdbserver killed, pid=%d, signal=%s\n", pid, signal_buf);
                gdb_pid = -1;
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

    CHECK((result = read(sfd, &fdsi, sizeof(struct signalfd_siginfo))) != -1);
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

int gdb_pipe_handler()
{
    char buf[0x100];
    memset(buf, 0, sizeof(buf));
    CHECK(read(gdb_pipe[0], buf, sizeof(buf)-1) != -1);
    gdb_output(buf);
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

int disconnect_gdb()
{
    socklen_t client_addr_size;
    char buf[0x10];

    if(gdb_client_addr.sin6_family)
    {
        client_addr_size = sizeof(gdb_client_addr);
        memset(buf, 0, sizeof(buf));
        buf[0] = COMMAND_GDB_LOGOUT;
        CHECK(sendto(command_sock, buf, 1, 0, (struct sockaddr *)&gdb_client_addr, client_addr_size) != -1);
    }

    return 0;
}

int main(int argc, char **args)
{
    struct epoll_event events[0x10];
    int event_num;
    int run;
    int i;
    int output_mode;

    tty = isatty(STDOUT_FILENO);

    if(tty)
    {
        output_mode = _IONBF;
    }
    else
    {
        output_mode = _IOLBF;
    }

    setvbuf(stdin, NULL, output_mode, 0);
    setvbuf(stdout, NULL, output_mode, 0);
    setvbuf(stderr, NULL, output_mode, 0);

    if(argc > 1)
    {
        popen_arg = args[1];
    }
    else
    {
        if(access(service_args[0], X_OK) == -1)
        {
            error_printf("'%s' is not executable!\n", service_args[0]);
            exit(EXIT_FAILURE);
        }
    }

    CHECK(pipe(gdb_pipe) != -1);

    CHECK(pipe(strace_pipe) != -1);

    CHECK((epollfd = epoll_create(6)) != -1);

    init_socket();

    set_sig_handler();

    monitor_fd(command_sock);
    if(popen_arg == NULL)
    {
        monitor_fd(service_sock);
    }
    monitor_fd(sfd);
    monitor_fd(gdb_pipe[0]);
    monitor_fd(strace_pipe[0]);

    info_printf("Start debugging service, pid=%d, version=%s\n", getpid(), VERSION);
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
            else if(popen_arg == NULL && events[i].data.fd == service_sock)
            {
                run = service_handler();
            }
            else if(events[i].data.fd == sfd)
            {
                run = signal_handler();
            }
            else if(events[i].data.fd == gdb_pipe[0])
            {
                run = gdb_pipe_handler();
            }
            else if(events[i].data.fd == strace_pipe[0])
            {
                run = strace_pipe_handler();
            }
        }
    }

    disconnect_gdb();

    info_printf("Exit debugging service, pid=%d\n", getpid());

    return 0;
}
