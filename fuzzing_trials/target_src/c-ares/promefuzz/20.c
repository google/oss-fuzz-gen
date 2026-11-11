// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_strerror at ares_strerror.c:30:13 in ares.h
// ares_inet_ntop at inet_ntop.c:64:20 in ares.h
// ares_inet_ntop at inet_ntop.c:64:20 in ares.h
// ares_freeaddrinfo at ares_freeaddrinfo.c:57:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void fuzz_ares_strerror(int code) {
    const char *error_str = ares_strerror(code);
    if (error_str) {
        // Do something with the error string if needed
    }
}

static void fuzz_ares_inet_ntop(int af, const void *src, size_t src_size) {
    char dst[INET6_ADDRSTRLEN];
    if (af == AF_INET && src_size >= sizeof(struct in_addr)) {
        ares_inet_ntop(af, src, dst, sizeof(dst));
    } else if (af == AF_INET6 && src_size >= sizeof(struct in6_addr)) {
        ares_inet_ntop(af, src, dst, sizeof(dst));
    }
}

static void fuzz_ares_freeaddrinfo(struct ares_addrinfo *ai) {
    if (ai != NULL) {
        ares_freeaddrinfo(ai);
    }
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    int code = *(int *)Data;
    fuzz_ares_strerror(code);

    if (Size < sizeof(int) + sizeof(int)) {
        return 0;
    }

    int af = *(int *)(Data + sizeof(int));
    const void *src = Data + sizeof(int) + sizeof(int);
    size_t remaining_size = Size - sizeof(int) - sizeof(int);

    fuzz_ares_inet_ntop(af, src, remaining_size);

    if (Size < sizeof(int) + sizeof(int) + sizeof(struct ares_addrinfo)) {
        return 0;
    }

    struct ares_addrinfo *ai = NULL;
    ai = (struct ares_addrinfo *)malloc(sizeof(struct ares_addrinfo));
    if (ai) {
        memset(ai, 0, sizeof(struct ares_addrinfo));
        fuzz_ares_freeaddrinfo(ai);
    }

    return 0;
}