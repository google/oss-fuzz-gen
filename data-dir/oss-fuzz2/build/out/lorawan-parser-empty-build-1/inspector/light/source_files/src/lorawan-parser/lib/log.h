#ifndef __LOG_H__
#define __LOG_H__
#include <stdio.h>
#include <stdint.h>

typedef enum{
	LOG_LEVEL_QUIET,
	LOG_LEVEL_NORMAL,
	LOG_LEVEL_VERBOSE,
}log_level_t;

#define LOG_FATAL  0
#define LOG_ERROR  1
#define LOG_WARN   2
#define LOG_INFO   3
#define LOG_DEBUG  4
#define LOG_NORMAL 5

int log_init(log_level_t level);
//void log_puts(int priority, const char *format, ...);
//void log_hex(int priority, const uint8_t *buf, int len, const char *format, ...);
void log_line(void);

int log_puts(int priority, char *fmt, ...);

#endif
