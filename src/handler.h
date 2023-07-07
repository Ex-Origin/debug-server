#ifndef _H_DEBUG_SERVER_COMMAND_
#define _H_DEBUG_SERVER_COMMAND_

int command_handler();
int service_handler();
int signal_handler();
int gdbserver_pipe_handler();
int strace_pipe_handler();
int disconnect_gdb();
int start_service(int client_sock);

#endif