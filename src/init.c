#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include "fd.h"
#include "log.h"
#include "config.h"
#include "arg.h"
#include "pid.h"

int init_socket()
{
    struct sockaddr_in6 server_addr;
    int nOptval;

    // Command socket
    CHECK((command_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) != -1);

    // Don't wait WAIT signal.
    nOptval = 1;
    CHECK(setsockopt(command_socket, SOL_SOCKET, SO_REUSEADDR, &nOptval, sizeof(int)) != -1);

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::", &server_addr.sin6_addr);
    server_addr.sin6_port = htons(COMMAND_PORT);

    // Bind the socket to the server address
    CHECK(bind(command_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) != -1);

    if(arg_opt_e)
    {
        // Service socket
        CHECK((service_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) != -1);

        // Don't wait WAIT signal.
        nOptval = 1;
        CHECK(setsockopt(service_socket, SOL_SOCKET, SO_REUSEADDR, &nOptval, sizeof(int)) != -1);

        // Configure server address
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "::", &server_addr.sin6_addr);
        server_addr.sin6_port = htons(SERVICE_PORT);

        // Bind the socket to the server address
        CHECK(bind(service_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) != -1);

        CHECK(listen(service_socket, 64) != -1);
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

    CHECK((signal_fd = signalfd(-1, &new_mask, 0)) != -1);

    return 0;
}

int monitor_fd(int fd)
{
    struct epoll_event event;

    event.events = EPOLLIN;
	event.data.fd = fd;

    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) != -1);

    return 0;
}

int init_fd()
{
    CHECK(pipe(gdbserver_pipe) != -1);

    CHECK(pipe(strace_pipe) != -1);

    CHECK((epoll_fd = epoll_create(6)) != -1);

    init_socket();

    set_sig_handler();

    monitor_fd(command_socket);
    if(arg_opt_e)
    {
        monitor_fd(service_socket);
    }
    monitor_fd(signal_fd);
    monitor_fd(gdbserver_pipe[0]);
    monitor_fd(strace_pipe[0]);

    return 0;
}