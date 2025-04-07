#ifndef TEST_H
#define TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __BORLANDC__
#define __FUNCTION__ __FUNC__
#endif

#define TEST_TRUE(a)                                                           \
    {                                                                          \
        if (!(a)) {                                                            \
            printf("%s[%s:%d]: TEST_TRUE failed!\n", __FUNCTION__, __FILE__,   \
                   __LINE__);                                                  \
            exit(1);                                                           \
        }                                                                      \
    }
#define TEST_FALSE(a)                                                          \
    {                                                                          \
        if (a) {                                                               \
            printf("%s[%s:%d]: TEST_FALSE failed!\n", __FUNCTION__, __FILE__,  \
                   __LINE__);                                                  \
            exit(1);                                                           \
        }                                                                      \
    }
#define TEST_EQUAL(a, b)                                                       \
    {                                                                          \
        if (a != b) {                                                          \
            printf("%s[%s:%d]: TEST_EQUAL failed! %lld != %lld \n",            \
                   __FUNCTION__, __FILE__, __LINE__, (long long int)a,         \
                   (long long int)b);                                          \
            exit(1);                                                           \
        }                                                                      \
    }
#define TEST_NOT_EQUAL(a, b)                                                   \
    {                                                                          \
        if (a == b) {                                                          \
            printf("%s[%s:%d]: TEST_NOT_EQUAL failed!\n", __FUNCTION__,        \
                   __FILE__, __LINE__);                                        \
            exit(1);                                                           \
        }                                                                      \
    }
#define TEST_STRING_EQUAL(a, b)                                                \
    {                                                                          \
        if (strcmp(a, b) != 0) {                                               \
            printf("%s[%s:%d]: TEST_STRING_EQUAL failed!\n", __FUNCTION__,     \
                   __FILE__, __LINE__);                                        \
            exit(1);                                                           \
        }                                                                      \
    }
#define TEST_NULL(a)                                                           \
    {                                                                          \
        if (a != NULL) {                                                       \
            printf("%s[%s:%d]: TEST_NULL failed!\n", __FUNCTION__, __FILE__,   \
                   __LINE__);                                                  \
            exit(1);                                                           \
        }                                                                      \
    }
#define TEST_NOT_NULL(a)                                                       \
    {                                                                          \
        if (a == NULL) {                                                       \
            printf("%s[%s:%d]: TEST_NOT_NULL failed!\n", __FUNCTION__,         \
                   __FILE__, __LINE__);                                        \
            exit(1);                                                           \
        }                                                                      \
    }
#define TEST_CONTAINS(haystack, needle)                                        \
    {                                                                          \
        size_t __i;                                                            \
        for(__i = 0; __i < haystack.size(); __i++)                             \
        {                                                                      \
            if(haystack.at(__i) == needle) break;                              \
        }                                                                      \
        TEST_NOT_EQUAL(__i, haystack.size());                                  \
    }

#endif