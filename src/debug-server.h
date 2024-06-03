#ifndef _H_DEBUG_SERVER_
#define _H_DEBUG_SERVER_

#define SERVICE_PORT    9541
#define COMMAND_PORT    9545
#define GDBSERVER_PORT  9549

#define VERSION         "1.3.3"

#define COMMAND_GDB_REGISTER        0x01
#define COMMAND_GDBSERVER_ATTACH    0x02
#define COMMAND_STRACE_ATTACH       0x03
#define COMMAND_GET_ADDRESS         0x04
#define COMMAND_GDB_LOGOUT          0x05
#define COMMAND_RUN_SERVICE         0x06

#define OK_GREEN        "\033[92m"
#define WARNING_YELLOW  "\033[93m"
#define FAIL_RED        "\033[91m"
#define END_CLEAN       "\033[0m"
#define GDB_COLOR       "\033[96m"
#define STRACE_COLOR    "\033[95m"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
/**
 * The value must be TRUE, or the program will break down.
 * e.g., the value is thing what the program need to do.
 **/
#define CHECK(value)                                                          \
    {                                                                         \
        if ((value) == 0)                                                     \
        {                                                                     \
            error_printf("%s  %s:%d\n", strerror(errno), __FILE__, __LINE__); \
            exit(EXIT_FAILURE);                                               \
        }                                                                     \
    }

int tty_init();
int debug_printf(const char *format, ...);
int info_printf(const char *format, ...);
int warning_printf(const char *format, ...);
int error_printf(const char *format, ...);
int gdbserver_output(char *msg);
int strace_output(char *msg);

extern int arg_opt_e;
extern int arg_opt_p;
extern int arg_opt_o;
extern int arg_opt_m;
// halt at entry point
extern int arg_opt_s;
extern int arg_opt_v;
extern int arg_opt_n;
extern int arg_opt_u;
extern int arg_opt_6;
extern char **arg_execve_argv;
extern char *arg_popen;
extern int arg_pid;

int parsing_argv(int argc, char *argv[]);

extern int stopped;

int close_fd();

#include <arpa/inet.h>

extern int service_socket;
extern int command_socket;
extern int signal_fd;
extern int epoll_fd;
extern int gdbserver_pipe[2];
extern int strace_pipe[2];

extern struct sockaddr_in6 gdb_client_address;

int command_handler();
int service_handler();
int signal_handler();
int gdbserver_pipe_handler();
int strace_pipe_handler();
int disconnect_gdb();
int start_service(int client_sock);

int init_fd();

#include <sys/signalfd.h>

extern int service_pid;
extern int gdbserver_pid;
extern int strace_pid;

extern sigset_t old_mask;

int gdbserver_attach_pid(int pid);
int strace_attach_pid(int pid);

#endif