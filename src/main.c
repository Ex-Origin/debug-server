#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "debug-server.h"

int main(int argc, char *argv[])
{
    int run, event_num, i;
    struct epoll_event events[0x10];

    parsing_argv(argc, argv);
    tty_init();
    init_fd();

    info_printf("Start debugging service, pid=%d, version=%s\n", getpid(), VERSION);
    run = 1;
    while(run)
    {
        event_num = epoll_wait(epoll_fd, events, sizeof(events)/sizeof(events[0]), -1);
        for(i = 0; i < event_num; i++)
        {
            if(events[i].data.fd == command_socket)
            {
                run = command_handler();
            }
            else if(events[i].data.fd == service_socket)
            {
                run = service_handler();
            }
            else if(events[i].data.fd == signal_fd)
            {
                run = signal_handler();
            }
            else if(events[i].data.fd == gdbserver_pipe[0])
            {
                run = gdbserver_pipe_handler();
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