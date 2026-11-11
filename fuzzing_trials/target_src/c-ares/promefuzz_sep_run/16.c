// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_strerror at ares_strerror.c:30:13 in ares.h
// ares_inet_ntop at inet_ntop.c:64:20 in ares.h
// ares_freeaddrinfo at ares_freeaddrinfo.c:57:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "ares.h"

static void fuzz_ares_strerror(int code) {
    const char *error_str = ares_strerror(code);
    if (error_str) {
        // Optionally, perform some operation with error_str
    }
}

static void fuzz_ares_inet_ntop(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct in6_addr) + 1) return; // Ensure we have enough data

    int af = (Data[0] % 2 == 0) ? AF_INET : AF_INET6; // Choose between AF_INET and AF_INET6
    char dst[INET6_ADDRSTRLEN]; // Buffer for output string
    const void *src = (const void *)(Data + 1); // Source buffer for address

    if (af == AF_INET && Size < sizeof(struct in_addr) + 1) return; // Ensure enough data for IPv4
    if (af == AF_INET6 && Size < sizeof(struct in6_addr) + 1) return; // Ensure enough data for IPv6

    const char *result = ares_inet_ntop(af, src, dst, sizeof(dst));
    if (result) {
        // Optionally, perform some operation with result
    }
}

static void fuzz_ares_freeaddrinfo() {
    struct ares_addrinfo *ai = NULL;
    ares_freeaddrinfo(ai);
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least one byte for error code

    int error_code = Data[0]; // Use the first byte as an error code
    fuzz_ares_strerror(error_code);

    fuzz_ares_inet_ntop(Data, Size);

    fuzz_ares_freeaddrinfo();

    return 0;
}