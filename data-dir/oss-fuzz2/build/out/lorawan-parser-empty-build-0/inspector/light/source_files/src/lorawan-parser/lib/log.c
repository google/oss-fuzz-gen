#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "log.h"

#define LOG_STRFMT_LEN              (10)

#if defined _WIN32 || defined __CYGWIN__
#ifndef WIN32
#define WIN32
#endif // WIN32
#endif // __MINGW32__

#ifndef WIN32
#include <pthread.h>
#else
#  include <windows.h>
#  include <winerror.h>
#endif // WIN32

static log_level_t log_level;

#ifndef WIN32
static pthread_mutex_t log_mutex;
#endif // WIN32

int log_init(log_level_t level)
{
#ifndef WIN32
    int ret = pthread_mutex_init(&log_mutex, NULL);
    if (ret != 0) {
        return -1;
    }
#endif // WIN32

    log_level = level;
    return 0;
}

int log_puts(int priority, char *fmt, ...)
{
    int i = 0, d, ret, len, j;
    char c, *s;
    uint8_t *hbuf;
    double f;
    char strfmt[LOG_STRFMT_LEN+2];
    va_list ap;

#ifndef WIN32
    pthread_mutex_lock(&log_mutex);
#endif // WIN32

    /*Windows doesn't support ANSI escape sequences*/
#ifdef WIN32
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    WORD saved_attributes;
    WORD textAttributes;
    /* Save current attributes */
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    saved_attributes = consoleInfo.wAttributes;
    textAttributes = saved_attributes;

    switch (priority) {
        case LOG_FATAL:
            //foregroud white, background red
            textAttributes = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY | BACKGROUND_RED;
            break;
        case LOG_ERROR:
            // red
            textAttributes = FOREGROUND_RED;
            break;
        case LOG_WARN:
            // yellow
            textAttributes = FOREGROUND_GREEN | FOREGROUND_RED;
            break;
        case LOG_INFO:
            // green
            textAttributes = FOREGROUND_GREEN;
            break;
        case LOG_DEBUG:
            // highlight
            textAttributes = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY;
            break;
        case LOG_NORMAL:
        default:
            //printf("\033[32m");
            break;
    }
    SetConsoleTextAttribute(hConsole, textAttributes);
#else
    if(isatty(fileno(stdout))){
        switch (priority) {
        case LOG_FATAL:
            //foregroud white, background red
            printf("\033[37;41;1m");
            break;
        case LOG_ERROR:
            // red
            printf("\033[31m");
            break;
        case LOG_WARN:
            // yellow
            printf("\033[33m");
            break;
        case LOG_INFO:
            // green
            printf("\033[32;2m");
            break;
        case LOG_DEBUG:
            // bold
            printf("\033[1m");
            break;
        case LOG_NORMAL:
        default:
            //printf("\033[32m");
            break;
        }
    }
#endif

    if(fmt != NULL){
        va_start(ap, fmt);
        i = 0;
        while(*fmt){
            if(*fmt == '%'){
                strfmt[0] = '%';
                j=1;
                while( ( fmt[j]>='0' && fmt[j]<='9' ) ||
                      ( fmt[j]== '-' ) || ( fmt[j]== '+' ) || ( fmt[j]== '.' ) ){
                    strfmt[j] = fmt[j];
                    j++;
                    if(j == LOG_STRFMT_LEN){
                        break;
                    }
                }
                strfmt[j] = fmt[j];
                fmt += j;
                j++;
                strfmt[j] = '\0';

                switch(*fmt){
                case '%':
                    ret = printf(strfmt);
                    i+=ret;
                    break;
                case 'd':
                    d = va_arg(ap, int);
                    ret = printf(strfmt, d);
                    i+=ret;
                    break;
                case 'u':
                    d = va_arg(ap, int);
                    ret = printf(strfmt, (uint32_t)d);
                    i+=ret;
                    break;
                case 'x':
                case 'X':
                    d = va_arg(ap, int);
                    ret = printf(strfmt, d);
                    i+=ret;
                    break;
                case 'h':
                case 'H':
                    hbuf = va_arg(ap, uint8_t *);
                    len = va_arg(ap, int);
                    for(d=0; d<len; d++){
                        if(*fmt == 'h'){
                            ret = printf("%02X", hbuf[d]);
                        }else{
                            ret = printf("%02X ", hbuf[d]);
                        }
                        i+=ret;
                    }
                    break;
                case 's':
                    s = va_arg(ap, char *);
                    ret = printf(strfmt, s);
                    i+=ret;
                    break;
                case 'c':
                    c = (char)va_arg(ap, int);
                    ret = printf(strfmt, c);
                    i+=ret;
                    break;
                case 'f':
                    f = va_arg(ap, double);
                    ret = printf(strfmt, f);
                    i+=ret;
                    break;
                }
                fmt++;
            }else{
                fputc(*fmt++, stdout);
                i++;
            }
        }
        va_end(ap);
    }

#ifdef WIN32
    /* Restore original attributes */
    SetConsoleTextAttribute(hConsole, saved_attributes);
#else
    if(isatty(fileno(stdout))){
        printf("\033[0m");
    }
#endif

    printf("\n");
    fflush(stdout);
    i++;

#ifndef WIN32
    pthread_mutex_unlock(&log_mutex);
#endif // WIN32

    return i;
}

void log_line(void)
{
#ifndef WIN32
    pthread_mutex_lock(&log_mutex);
#endif // WIN32

    printf("\n--------------------------------------------------------------------------------\n");

#ifndef WIN32
    pthread_mutex_unlock(&log_mutex);
#endif // WIN32
}
