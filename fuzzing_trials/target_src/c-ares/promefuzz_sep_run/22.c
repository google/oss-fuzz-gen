// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_library_init at ares_library_init.c:108:5 in ares.h
// ares_init at ares_init.c:67:5 in ares.h
// ares_set_local_ip4 at ares_init.c:546:6 in ares.h
// ares_set_local_dev at ares_init.c:568:6 in ares.h
// ares_gethostbyaddr at ares_gethostbyaddr.c:108:6 in ares.h
// ares_getnameinfo at ares_getnameinfo.c:188:6 in ares.h
// ares_reinit at ares_init.c:407:15 in ares.h
// ares_cancel at ares_cancel.c:34:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ares.h>

static void dummy_callback(void *arg, int status, int timeouts, struct hostent *host) {
    // Dummy callback function
}

static void dummy_nameinfo_callback(void *arg, int status, int timeouts, char *node, char *service) {
    // Dummy nameinfo callback function
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    // Initialize ares library
    ares_library_init(ARES_LIB_INIT_ALL);

    // Create a channel
    ares_channel channel = NULL;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Prepare a dummy IPv4 address
    unsigned int local_ip4 = Size >= 4 ? *(unsigned int *)Data : 0;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = local_ip4;

    // Prepare a dummy device name
    char local_dev_name[33];  // 32 for the name and 1 for the null-terminator
    if (Size > 0) {
        size_t copy_size = (Size < 32) ? Size : 32;
        memcpy(local_dev_name, Data, copy_size);
        local_dev_name[copy_size] = '\0';  // Ensure null-termination
    } else {
        strcpy(local_dev_name, "dummy_dev");
    }

    // Prepare a dummy address for ares_gethostbyaddr
    const void *addr = NULL;
    int addrlen = 0;
    int family = AF_UNSPEC;
    if (Size >= sizeof(struct in_addr)) {
        addr = (const void *)Data;
        addrlen = sizeof(struct in_addr);
        family = AF_INET;
    }

    // Explore different API functions
    ares_set_local_ip4(channel, local_ip4);
    ares_set_local_dev(channel, local_dev_name);
    if (addr) {
        ares_gethostbyaddr(channel, addr, addrlen, family, dummy_callback, NULL);
    }
    ares_getnameinfo(channel, (const struct sockaddr *)&sa, sizeof(sa), 0, dummy_nameinfo_callback, NULL);
    ares_reinit(channel);
    ares_cancel(channel);

    // Cleanup
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}