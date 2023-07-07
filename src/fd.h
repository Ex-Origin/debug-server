#ifndef _H_DEBUG_SERVER_FD_
#define _H_DEBUG_SERVER_FD_

#include <arpa/inet.h>

extern int service_socket;
extern int command_socket;
extern int signal_fd;
extern int epoll_fd;
extern int gdbserver_pipe[2];
extern int strace_pipe[2];

extern struct sockaddr_in6 gdb_client_address;

#endif