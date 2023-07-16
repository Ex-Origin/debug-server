#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "debug-server.h"

int arg_opt_e = 0;
int arg_opt_p = 0;
int arg_opt_m = 0;
int arg_opt_s = 0;
int arg_opt_v = 0;
int arg_opt_n = 0;

char **arg_execve_argv = NULL;
char *arg_popen = NULL;

char **parsing_execve_str(char *cmd)
{
    char *ptr = NULL, **tmp, **argv = NULL;
    int argc = 0, max;
    
    max = 16;
    CHECK((argv = calloc(max, sizeof(char *))) != NULL);

    ptr = strtok(cmd, " ");
    while(1)
    {
        if(ptr == NULL || *ptr)
        {
            if(argc + 1 > max)
            {
                CHECK((tmp = realloc(argv, (max * 2) * sizeof(char *))) != NULL);
                argv = tmp;
                max = max * 2;
            }
            argv[argc++] = ptr;
        }
        if(ptr == NULL)
        {
            break;
        }
        ptr = strtok(NULL, " ");
    }

    return argv;
}

int help()
{
    fprintf(stderr, "Usage: debug-server [-hmsvn] [-e CMD] [-p CMD]\n"
                    "\n"
                    "debug-server " VERSION "\n"
                    "General:\n"
                    "  -e CMD   service argv\n"
                    "  -p CMD   get pid by popen\n"
                    "  -h       print help message\n"
                    "  -m       enable multi-service\n"
                    "  -s       halt at entry point\n"
                    "  -v       show debug information\n"
                    "  -n       disable address space randomization\n"
    );
    exit(EXIT_FAILURE);
}

int parsing_argv(int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "e:p:hmsvn")) != -1) {
        switch (opt) {
        case 'e':
            arg_opt_e = 1;
            arg_execve_argv = parsing_execve_str(optarg);
            break;
        case 'p':
            arg_opt_p = 1;
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
        default: /* '?' */
            help();
            break;
        }
    }
    if(!(arg_opt_e || arg_opt_p))
    {
        fprintf(stderr, "debug-server: must have -e CMD or -p CMD\n");
        help();
    }
    return 0;
}
