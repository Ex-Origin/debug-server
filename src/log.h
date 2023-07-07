#ifndef _H_DEBUG_SERVER_LOG_
#define _H_DEBUG_SERVER_LOG_

#define OK_GREEN        "\033[92m"
#define WARNING_YELLOW  "\033[93m"
#define FAIL_RED        "\033[91m"
#define END_CLEAN       "\033[0m"
#define GDB_COLOR       "\033[96m"
#define STRACE_COLOR    "\033[95m"

/**
 * The value must be TRUE, or the program will break down.
 * e.g., the value is thing what the program need to do.
 **/
#define CHECK(value)                                            \
    {                                                           \
        if ((value) == 0)                                       \
        {                                                       \
            error_printf("%m  %s:%d\n", __FILE__, __LINE__);    \
            exit(EXIT_FAILURE);                                 \
        }                                                       \
    }

int tty_init();
int debug_printf(const char *format, ...);
int info_printf(const char *format, ...);
int warning_printf(const char *format, ...);
int error_printf(const char *format, ...);
int gdbserver_output(char *msg);
int strace_output(char *msg);

#endif