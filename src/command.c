#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "debug-server.h"

int popen_to_int(char *cmd)
{
    FILE *fp = NULL;
    char buf[0x100];
    int result;

    CHECK((fp = popen(cmd, "r")) != NULL);
                
    memset(buf, 0, sizeof(buf));
    CHECK((result = fread(buf, sizeof(buf[0]), sizeof(buf)-1, fp)) >= 0);
                
    CHECK(pclose(fp) != -1);

    return atoi(buf);
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
    else
    {
        warning_printf("%s open failed.\n", buf);
    }
    return result;
}

int command_handler()
{
    char buf[0x100];
    socklen_t client_addr_size;
    struct sockaddr_in client_addr4;
    struct sockaddr_in6 client_addr6;
    int recv_len;
    unsigned char command, path_len;
    size_t addr = 0;
    char clientIP[INET6_ADDRSTRLEN], ip_buf[0x100];
    int clientPort;
    int pid;
    int gdb_attached = 0;

    if (arg_opt_6)
    {
        client_addr_size = sizeof(client_addr6);
        memset(buf, 0, sizeof(buf));
        recv_len = recvfrom(command_socket, buf, sizeof(buf)-1, 0, (struct sockaddr *)&client_addr6, &client_addr_size);
    }
    else
    {
        client_addr_size = sizeof(client_addr4);
        memset(buf, 0, sizeof(buf));
        recv_len = recvfrom(command_socket, buf, sizeof(buf)-1, 0, (struct sockaddr *)&client_addr4, &client_addr_size);
    }

    if (arg_opt_6)
    {
        memset(clientIP, 0, sizeof(clientIP));
        inet_ntop(AF_INET6, &(client_addr6.sin6_addr), clientIP, INET6_ADDRSTRLEN);
        memset(ip_buf, 0, sizeof(ip_buf));
        if (clientIP[0] == ':')
        {
            snprintf(ip_buf, sizeof(ip_buf)-1, "%s", clientIP + 7);
        }
        else
        {
            snprintf(ip_buf, sizeof(ip_buf)-1, "[%s]", clientIP);
        }
        clientPort = ntohs(client_addr6.sin6_port);
    }
    else
    {
        memset(clientIP, 0, sizeof(clientIP));
        inet_ntop(AF_INET, &(client_addr4.sin_addr), clientIP, INET_ADDRSTRLEN);
        memset(ip_buf, 0, sizeof(ip_buf));
        snprintf(ip_buf, sizeof(ip_buf)-1, "%s", clientIP);
        clientPort = ntohs(client_addr4.sin_port);
    }


    command = buf[0];
    switch(command)
    {
    case COMMAND_GDB_REGISTER:
        if (arg_opt_6)
        {
            memcpy(&gdb_client_address6, &client_addr6, sizeof(gdb_client_address6));
        }
        else
        {
            memcpy(&gdb_client_address4, &client_addr4, sizeof(gdb_client_address4));
        }
        info_printf("%s gdb client registered.\n", ip_buf);

        if (arg_opt_6)
        {
            client_addr_size = sizeof(client_addr6);
            CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&client_addr6, client_addr_size) != -1);
        }
        else
        {
            client_addr_size = sizeof(client_addr4);
            CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&client_addr4, client_addr_size) != -1);
        }

        break;
    case COMMAND_GDBSERVER_ATTACH:
        debug_printf("Receive %s:%d from command_sock to COMMAND_GDBSERVER_ATTACH\n", ip_buf, clientPort);
        if((arg_opt_6 && gdb_client_address6.sin6_family) || ((!arg_opt_6) && gdb_client_address4.sin_family))
        {
            if(arg_opt_p)
            {
                pid = arg_pid;
                if(pid)
                {
                    gdb_attached = gdbserver_attach_pid(pid);
                }
                else
                {
                    warning_printf("There is an issue with the PID \"%s\".\n", arg_popen);
                }
            }
            else if(arg_opt_o)
            {
                pid = popen_to_int(arg_popen);
                if(pid)
                {
                    gdb_attached = gdbserver_attach_pid(pid);
                }
                else
                {
                    warning_printf("There is an issue with the CMD \"%s\".\n", arg_popen);
                }
            }
            else if(service_pid != -1)
            {
                gdb_attached = gdbserver_attach_pid(service_pid);
            }
            else
            {
                warning_printf("There are no PIDs available for tracing!\n");
            }

            if(gdb_attached)
            {
                if (arg_opt_6)
                {
                    client_addr_size = sizeof(gdb_client_address6);
                    // Send the received data back to the two client
                    CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&gdb_client_address6, client_addr_size) != -1);
                }
                else
                {
                    client_addr_size = sizeof(gdb_client_address4);
                    // Send the received data back to the two client
                    CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&gdb_client_address4, client_addr_size) != -1);
                }
            }
        }
        else
        {
            warning_printf("There is no gdb client\n");
        }
        
        if (arg_opt_6)
        {
            client_addr_size = sizeof(client_addr6);
            CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&client_addr6, client_addr_size) != -1);
        }
        else
        {
            client_addr_size = sizeof(client_addr4);
            CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&client_addr4, client_addr_size) != -1);
        }
        
        break;
    case COMMAND_STRACE_ATTACH:
        debug_printf("Receive %s:%d from command_sock to COMMAND_STRACE_ATTACH\n", ip_buf, clientPort);
        if(arg_opt_p)
        {
            pid = arg_pid;
            if(pid)
            {
                strace_attach_pid(pid);
            }
            else
            {
                warning_printf("There is an issue with the PID \"%s\".\n", arg_popen);
            }
        }
        if(arg_opt_o)
        {
            pid = popen_to_int(arg_popen);
            if(pid)
            {
                strace_attach_pid(pid);
            }
            else
            {
                warning_printf("There is an issue with the CMD \"%s\".\n", arg_popen);
            }
        }
        else if(service_pid != -1)
        {
            strace_attach_pid(service_pid);
        }
        else
        {
            warning_printf("There are no PIDs available for tracing!\n");
        }

        if (arg_opt_6)
        {
            client_addr_size = sizeof(client_addr6);
            CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&client_addr6, client_addr_size) != -1);
        }
        else
        {
            client_addr_size = sizeof(client_addr4);
            CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&client_addr4, client_addr_size) != -1);
        }
        
        break;
    case COMMAND_GET_ADDRESS:
        debug_printf("Receive %s:%d from command_sock to COMMAND_GET_ADDRESS\n", ip_buf, clientPort);
        addr = 0;
        if(arg_opt_o)
        {
            addr = get_address(popen_to_int(arg_popen), buf + 2);
        }
        else if(service_pid != -1)
        {
            addr = get_address(service_pid, buf + 2);
        }

        memset(buf, 0, sizeof(buf));
        buf[0] = COMMAND_GET_ADDRESS;
        buf[1] = sizeof(addr);
        *(size_t*)&buf[2] = addr;

        if (arg_opt_6)
        {
            client_addr_size = sizeof(client_addr6);
            CHECK(sendto(command_socket, buf, 2 + sizeof(addr), 0, (struct sockaddr *)&client_addr6, client_addr_size) != -1);
        }
        else
        {
            client_addr_size = sizeof(client_addr4);
            CHECK(sendto(command_socket, buf, 2 + sizeof(addr), 0, (struct sockaddr *)&client_addr4, client_addr_size) != -1);
        }
        
        
        break;
    case COMMAND_GDB_LOGOUT:
        warning_printf("Receive COMMAND_GDB_LOGOUT from %s:%d\n", ip_buf, clientPort);
        break;
    case COMMAND_RUN_SERVICE:
        debug_printf("Receive %s:%d from command_sock to COMMAND_RUN_SERVICE\n", ip_buf, clientPort);
        start_service(0);

        if (arg_opt_6)
        {
            client_addr_size = sizeof(client_addr6);
            CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&client_addr6, client_addr_size) != -1);
        }
        else
        {
            client_addr_size = sizeof(client_addr4);
            CHECK(sendto(command_socket, buf, recv_len, 0, (struct sockaddr *)&client_addr4, client_addr_size) != -1);
        }

        break;
    default:
        warning_printf("Unknown command 0x%02X\n", command);
        break;
    }

    return 1;
}

int disconnect_gdb()
{
    socklen_t client_addr_size;
    char buf[0x10];

    if (arg_opt_6)
    {
        if(gdb_client_address6.sin6_family)
        {
            client_addr_size = sizeof(gdb_client_address6);
            memset(buf, 0, sizeof(buf));
            buf[0] = COMMAND_GDB_LOGOUT;
            CHECK(sendto(command_socket, buf, 1, 0, (struct sockaddr *)&gdb_client_address6, client_addr_size) != -1);
        }
    }
    else
    {
        if(gdb_client_address4.sin_family)
        {
            client_addr_size = sizeof(gdb_client_address4);
            memset(buf, 0, sizeof(buf));
            buf[0] = COMMAND_GDB_LOGOUT;
            CHECK(sendto(command_socket, buf, 1, 0, (struct sockaddr *)&gdb_client_address4, client_addr_size) != -1);
        }
    }

    return 0;
}