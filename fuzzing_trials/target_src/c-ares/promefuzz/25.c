// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_parse_ptr_reply at ares_parse_ptr_reply.c:186:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_parse_ns_reply at ares_parse_ns_reply.c:39:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_parse_naptr_reply at ares_parse_naptr_reply.c:29:5 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_parse_soa_reply at ares_parse_soa_reply.c:30:5 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_parse_caa_reply at ares_parse_caa_reply.c:30:5 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_parse_a_reply at ares_parse_a_reply.c:48:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <netinet/in.h>

static void fuzz_ares_parse_ptr_reply(const unsigned char *Data, size_t Size) {
    struct hostent *host = NULL;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int result = ares_parse_ptr_reply(Data, Size, &addr, sizeof(addr), AF_INET, &host);
    if (result == ARES_SUCCESS && host) {
        ares_free_hostent(host);
    }
}

static void fuzz_ares_parse_ns_reply(const unsigned char *Data, size_t Size) {
    struct hostent *host = NULL;
    int result = ares_parse_ns_reply(Data, Size, &host);
    if (result == ARES_SUCCESS && host) {
        ares_free_hostent(host);
    }
}

static void fuzz_ares_parse_naptr_reply(const unsigned char *Data, size_t Size) {
    struct ares_naptr_reply *naptr_out = NULL;
    int result = ares_parse_naptr_reply(Data, Size, &naptr_out);
    if (result == ARES_SUCCESS && naptr_out) {
        ares_free_data(naptr_out);
    }
}

static void fuzz_ares_parse_soa_reply(const unsigned char *Data, size_t Size) {
    struct ares_soa_reply *soa_out = NULL;
    int result = ares_parse_soa_reply(Data, Size, &soa_out);
    if (result == ARES_SUCCESS && soa_out) {
        ares_free_data(soa_out);
    }
}

static void fuzz_ares_parse_caa_reply(const unsigned char *Data, size_t Size) {
    struct ares_caa_reply *caa_out = NULL;
    int result = ares_parse_caa_reply(Data, Size, &caa_out);
    if (result == ARES_SUCCESS && caa_out) {
        ares_free_data(caa_out);
    }
}

static void fuzz_ares_parse_a_reply(const unsigned char *Data, size_t Size) {
    struct hostent *host = NULL;
    struct ares_addrttl addrttls[10];
    int naddrttls = 10;
    int result = ares_parse_a_reply(Data, Size, &host, addrttls, &naddrttls);
    if (result == ARES_SUCCESS && host) {
        ares_free_hostent(host);
    }
}

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    fuzz_ares_parse_ptr_reply(Data, Size);
    fuzz_ares_parse_ns_reply(Data, Size);
    fuzz_ares_parse_naptr_reply(Data, Size);
    fuzz_ares_parse_soa_reply(Data, Size);
    fuzz_ares_parse_caa_reply(Data, Size);
    fuzz_ares_parse_a_reply(Data, Size);
    return 0;
}