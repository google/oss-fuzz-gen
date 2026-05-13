// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_parse_txt_reply at ares_parse_txt_reply.c:126:5 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_parse_ptr_reply at ares_parse_ptr_reply.c:186:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_parse_ns_reply at ares_parse_ns_reply.c:39:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_parse_soa_reply at ares_parse_soa_reply.c:30:5 in ares.h
// ares_free_data at ares_data.c:46:6 in ares.h
// ares_gethostbyname_file at ares_gethostbyname.c:335:5 in ares.h
// ares_free_hostent at ares_free_hostent.c:33:6 in ares.h
// ares_library_init at ares_library_init.c:108:5 in ares.h
// ares_init at ares_init.c:67:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>
#include <netinet/in.h> // For sockaddr_in
#include <netdb.h> // For struct hostent

static void fuzz_ares_free_hostent(struct hostent *host) {
    ares_free_hostent(host);
}

static void fuzz_ares_parse_txt_reply(const unsigned char *abuf, int alen) {
    struct ares_txt_reply *txt_out = NULL;
    ares_parse_txt_reply(abuf, alen, &txt_out);
    if (txt_out) {
        ares_free_data(txt_out);
    }
}

static void fuzz_ares_parse_ptr_reply(const unsigned char *abuf, int alen, const void *addr, int addrlen, int family) {
    struct hostent *host = NULL;
    ares_parse_ptr_reply(abuf, alen, addr, addrlen, family, &host);
    if (host) {
        ares_free_hostent(host);
    }
}

static void fuzz_ares_parse_ns_reply(const unsigned char *abuf, int alen) {
    struct hostent *host = NULL;
    ares_parse_ns_reply(abuf, alen, &host);
    if (host) {
        ares_free_hostent(host);
    }
}

static void fuzz_ares_parse_soa_reply(const unsigned char *abuf, int alen) {
    struct ares_soa_reply *soa_out = NULL;
    ares_parse_soa_reply(abuf, alen, &soa_out);
    if (soa_out) {
        ares_free_data(soa_out);
    }
}

static void fuzz_ares_gethostbyname_file(ares_channel channel, const char *name, int family) {
    struct hostent *host = NULL;
    ares_gethostbyname_file(channel, name, family, &host);
    if (host) {
        ares_free_hostent(host);
    }
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    unsigned char *abuf = (unsigned char *)Data;
    int alen = (int)Size;

    // Fuzz ares_free_hostent
    struct hostent *host = (struct hostent *)calloc(1, sizeof(struct hostent));
    if (host) {
        fuzz_ares_free_hostent(host);
        // Removed the redundant free(host) call to avoid double-free
    }

    // Fuzz ares_parse_txt_reply
    fuzz_ares_parse_txt_reply(abuf, alen);

    // Fuzz ares_parse_ptr_reply
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    fuzz_ares_parse_ptr_reply(abuf, alen, &addr, sizeof(addr), AF_INET);

    // Fuzz ares_parse_ns_reply
    fuzz_ares_parse_ns_reply(abuf, alen);

    // Fuzz ares_parse_soa_reply
    fuzz_ares_parse_soa_reply(abuf, alen);

    // Fuzz ares_gethostbyname_file
    ares_channel channel;
    ares_library_init(ARES_LIB_INIT_ALL);
    ares_init(&channel);
    fuzz_ares_gethostbyname_file(channel, "./dummy_file", AF_INET);
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}