#ifndef _H_DEBUG_SERVER_ARG_
#define _H_DEBUG_SERVER_ARG_

extern int arg_opt_e;
extern int arg_opt_p;
extern int arg_opt_m;
// halt at entry point
extern int arg_opt_s;
extern int arg_opt_v;
extern int arg_opt_n;
extern char **arg_execve_argv;
extern char *arg_popen;

int parsing_argv(int argc, char *argv[]);

#endif