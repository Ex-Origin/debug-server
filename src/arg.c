#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "debug-server.h"

int arg_opt_e = 0;
int arg_opt_p = 0;
int arg_opt_o = 0;
int arg_opt_m = 0;
int arg_opt_s = 0;
int arg_opt_v = 0;
int arg_opt_n = 0;
int arg_opt_u = 0;
int arg_opt_6 = 0;

char **arg_execve_argv = NULL;
char *arg_popen = NULL;
int arg_pid = -1;

char **parsing_execve_str(char *cmd)
{
    char *ptr = cmd, **tmp, **argv = NULL;
    int argc = 0, max;
    int in_single_quote = 0, in_double_quote = 0;
    
    max = 16;
    CHECK((argv = calloc(max, sizeof(char *))) != NULL);

    while (*ptr != '\0')
    {
        char *arg_start = ptr;
        char *arg = malloc(strlen(ptr) + 1);  // Temporary buffer to hold the parsed argument
        CHECK(arg != NULL);
        int arg_len = 0;

        while (*ptr != '\0')
        {
            if (*ptr == '"' && !in_single_quote) {
                in_double_quote = !in_double_quote;
            } else if (*ptr == '\'' && !in_double_quote) {
                in_single_quote = !in_single_quote;
            } else if (*ptr == ' ' && !in_single_quote && !in_double_quote) {
                ptr ++;
                break;  // Space outside quotes means end of argument
            } else {
                arg[arg_len++] = *ptr;  // Add the character to the argument
            }
            ptr ++;
        }
        
        arg[arg_len] = '\0';  // Null-terminate the argument

        if (argc + 1 > max)
        {
            CHECK((tmp = realloc(argv, (max * 2) * sizeof(char *))) != NULL);
            argv = tmp;
            max = max * 2;
        }
        argv[argc++] = arg;
    }

    if (in_single_quote || in_double_quote) {
        fprintf(stderr, "Error: Unmatched quote in input string\n");
        exit(EXIT_FAILURE);
    }

    argv[argc] = NULL;  // Null-terminate the argument list

    return argv;
}

int help()
{
    fprintf(stderr, "Usage: debug-server [-hmsvn] [-e CMD] [-p PID] [-o CMD]\n"
                    "\n"
                    "debug-server " VERSION "\n"
                    "General:\n"
                    "  -e CMD   service argv\n"
                    "  -p PID   attach to PID\n"
                    "  -o CMD   get pid by popen\n"
                    "  -h       print help message\n"
                    "  -m       enable multi-service\n"
                    "  -s       halt at entry point\n"
                    "  -v       show debug information\n"
                    "  -n       disable address space randomization\n"
                    "  -u       do not limit memory\n"
                    "  -6       ipv6 mode\n"
    );
    exit(EXIT_FAILURE);
}

int parsing_argv(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "e:p:o:hmsvnu6")) != -1) {
        switch (opt) {
        case 'e':
            arg_opt_e = 1;
            arg_execve_argv = parsing_execve_str(optarg);
            break;
        case 'p':
            arg_opt_p = 1;
            arg_pid = atoi(optarg);
        case 'o':
            arg_opt_o = 1;
            arg_popen = optarg;
            break;
        case 'h':
            help();
            break;
        case 'm':
            arg_opt_m = 1;
            break;
        case 's':
            arg_opt_s = 1;
            break;
        case 'v':
            arg_opt_v = 1;
            break;
        case 'n':
            arg_opt_n = 1;
            break;
        case 'u':
            arg_opt_u = 1;
            break;
        case '6':
            arg_opt_6 = 1;
            break;
        default: /* '?' */
            help();
            break;
        }
    }
    if(!(arg_opt_e || arg_opt_p || arg_opt_o))
    {
        fprintf(stderr, "debug-server: must have -e CMD or -p PID or -o CMD\n");
        help();
    }
    return 0;
}
