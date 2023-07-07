#include "fd.h"

int service_socket      = -1;
int command_socket      = -1;
int signal_fd           = -1;
int epoll_fd            = -1;

int gdbserver_pipe[2]   = {-1, -1};
int strace_pipe[2]      = {-1, -1};

struct sockaddr_in6 gdb_client_address = {0};
