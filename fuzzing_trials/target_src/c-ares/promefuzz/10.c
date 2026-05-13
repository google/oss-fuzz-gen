// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_freeaddrinfo at ares_freeaddrinfo.c:57:6 in ares.h
// ares_init_options at ares_init.c:238:5 in ares.h
// ares_gethostbyaddr at ares_gethostbyaddr.c:108:6 in ares.h
// ares_getnameinfo at ares_getnameinfo.c:188:6 in ares.h
// ares_getaddrinfo at ares_getaddrinfo.c:695:6 in ares.h
// ares_reinit at ares_init.c:407:15 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>
#include <arpa/inet.h>

static void host_callback(void *arg, int status, int timeouts, struct hostent *host) {
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)host;
}

static void addrinfo_callback(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
    (void)arg;
    (void)status;
    (void)timeouts;
    if (res) {
        ares_freeaddrinfo(res);
    }
}

static void nameinfo_callback(void *arg, int status, int timeouts, char *node, char *service) {
    (void)arg;
    (void)status;
    (void)timeouts;
    (void)node;
    (void)service;
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;
    int status = ares_init_options(&channel, &options, optmask);

    if (status != ARES_SUCCESS) {
        return 0;
    }

    if (Size >= sizeof(struct in_addr)) {
        struct in_addr addr;
        memcpy(&addr, Data, sizeof(struct in_addr));

        ares_gethostbyaddr(channel, &addr, sizeof(struct in_addr), AF_INET, host_callback, NULL);
    }

    if (Size >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in sa;
        memcpy(&sa, Data, sizeof(struct sockaddr_in));

        ares_getnameinfo(channel, (struct sockaddr *)&sa, sizeof(struct sockaddr_in), 0, nameinfo_callback, NULL);
    }

    const char *node = "example.com";
    const char *service = "http";
    struct ares_addrinfo_hints hints;
    memset(&hints, 0, sizeof(hints));

    ares_getaddrinfo(channel, node, service, &hints, addrinfo_callback, NULL);

    ares_reinit(channel);

    ares_destroy(channel);

    return 0;
}