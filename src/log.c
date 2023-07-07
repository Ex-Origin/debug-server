#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include "arg.h"

int tty = 0;

int tty_init()
{
    int output_mode;
    tty = isatty(STDOUT_FILENO);

    if(tty)
    {
        output_mode = _IONBF;
    }
    else
    {
        output_mode = _IOLBF;
    }

    setvbuf(stdin, NULL, output_mode, 0);
    setvbuf(stdout, NULL, output_mode, 0);
    setvbuf(stderr, NULL, output_mode, 0);

    return 0;
}

int prefix_printf(FILE* fp, char *level)
{
    va_list args;
    // variables to store the date and time components
    int hours, minutes, seconds, day, month, year;
    // `time_t` is an arithmetic time type
    time_t now = 0;
    // localtime converts a `time_t` value to calendar time and
    // returns a pointer to a `tm` structure with its members
    // filled with the corresponding values
    struct tm *local;
    size_t result;

    now = time(NULL);
#ifdef TIME_OFFSET
    now = now + (TIME_OFFSET);
#endif
    local = localtime(&now);

    hours = local->tm_hour;         // get hours since midnight (0-23)
    minutes = local->tm_min;        // get minutes passed after the hour (0-59)
    seconds = local->tm_sec;        // get seconds passed after a minute (0-59)
 
    day = local->tm_mday;            // get day of month (1 to 31)
    month = local->tm_mon + 1;      // get month of year (0 to 11)
    year = local->tm_year + 1900;   // get year since 1900

    result = fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d | %-7s | ", year, month, day, hours, minutes, seconds, level);

    return result;
}

int debug_printf(const char *format, ...)
{
    va_list args;
    size_t result = -1;

    if(arg_opt_v)
    {
        prefix_printf(stdout, "DEBUG");
        va_start(args, format);
        result = vfprintf (stdout, format, args);
        va_end (args);
    }

    return result;
}

int info_printf(const char *format, ...)
{
    va_list args;
    size_t result;

    if(tty)
    {
        fprintf(stderr, OK_GREEN);
    }
    prefix_printf(stdout, "INFO");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    if(tty)
    {
        fprintf(stderr, END_CLEAN);
    }

    return result;
}

int warning_printf(const char *format, ...)
{
    va_list args;
    size_t result;
    
    if(tty)
    {
        fprintf(stderr, WARNING_YELLOW);
    }
    prefix_printf(stdout, "WARNING");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    if(tty)
    {
        fprintf(stderr, END_CLEAN);
    }

    return result;
}

int error_printf(const char *format, ...)
{
    va_list args;
    size_t result;
    
    if(tty)
    {
        fprintf(stderr, FAIL_RED);
    }
    prefix_printf(stderr, "ERROR");
    va_start(args, format);
    result = vfprintf (stderr, format, args);
    va_end (args);
    if(tty)
    {
        fprintf(stderr, END_CLEAN);
    }

    return result;
}

int gdbserver_output(char *msg)
{
    char *ptr = NULL;
    int result = 0;

    if(tty)
    {
        fprintf(stdout, WARNING_YELLOW);
    }

    ptr = strtok(msg, "\n");
    while(ptr != NULL)
    {
        prefix_printf(stdout, "GDB");
        result += fprintf(stdout, "%s\n", ptr);
        ptr = strtok(NULL, "\n");
    }

    if(tty)
    {
        fprintf(stdout, END_CLEAN);
    }

    return result;
}

int strace_output(char *msg)
{
    if(tty)
    {
        return fprintf(stdout, STRACE_COLOR "%s" END_CLEAN, msg);
    }
    else
    {
        return fprintf(stdout, "%s", msg);
    }
}
