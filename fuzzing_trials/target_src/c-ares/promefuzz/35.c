// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_inet_ntop at inet_ntop.c:64:20 in ares.h
// ares_dns_rr_get_addr at ares_dns_record.c:757:23 in ares_dns_record.h
// ares_dns_addr_to_ptr at ares_dns_record.c:1465:7 in ares_dns_record.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_dns_parse at ares_dns_parse.c:1310:15 in ares_dns_record.h
// ares_dns_record_destroy at ares_dns_record.c:223:6 in ares_dns_record.h
// ares_dns_pton at ares_hosts_file.c:103:13 in ares_dns_record.h
// ares_dns_rr_get_addr6 at ares_dns_record.c:774:29 in ares_dns_record.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ares.h>
#include <ares_dns_record.h>

static void fuzz_ares_inet_ntop(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct in_addr)) return;

    int af = AF_INET;
    char dst[INET6_ADDRSTRLEN];
    const void *src = (const void *)Data;

    if (Size >= sizeof(struct in6_addr)) {
        af = AF_INET6;
        src = (const void *)Data;
    }

    ares_inet_ntop(af, src, dst, sizeof(dst));
}

static void fuzz_ares_dns_rr_get_addr(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(ares_dns_rr_key_t)) return;

    const ares_dns_rr_t *dns_rr = NULL; // Assuming valid pointer setup elsewhere
    ares_dns_rr_key_t key = (ares_dns_rr_key_t)Data[Size - 1];

    ares_dns_rr_get_addr(dns_rr, key);
}

static void fuzz_ares_dns_addr_to_ptr(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct ares_addr)) return;

    const struct ares_addr *addr = (const struct ares_addr *)Data;
    char *result = ares_dns_addr_to_ptr(addr);
    if (result) {
        ares_free_string(result);
    }
}

static void fuzz_ares_dns_parse(const uint8_t *Data, size_t Size) {
    ares_dns_record_t *dnsrec = NULL;
    unsigned int flags = 0; // You can modify flags as needed

    ares_dns_parse(Data, Size, flags, &dnsrec);
    if (dnsrec) {
        ares_dns_record_destroy(dnsrec);
    }
}

static void fuzz_ares_dns_pton(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    char ipaddr[INET6_ADDRSTRLEN];
    size_t copy_size = Size > INET6_ADDRSTRLEN - 1 ? INET6_ADDRSTRLEN - 1 : Size;
    memcpy(ipaddr, Data, copy_size);
    ipaddr[copy_size] = '\0';

    struct ares_addr addr;
    addr.family = AF_UNSPEC;
    size_t out_len;

    ares_dns_pton(ipaddr, &addr, &out_len);
}

static void fuzz_ares_dns_rr_get_addr6(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(ares_dns_rr_key_t)) return;

    const ares_dns_rr_t *dns_rr = NULL; // Assuming valid pointer setup elsewhere
    ares_dns_rr_key_t key = (ares_dns_rr_key_t)Data[Size - 1];

    ares_dns_rr_get_addr6(dns_rr, key);
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    fuzz_ares_inet_ntop(Data, Size);
    fuzz_ares_dns_rr_get_addr(Data, Size);
    fuzz_ares_dns_addr_to_ptr(Data, Size);
    fuzz_ares_dns_parse(Data, Size);
    fuzz_ares_dns_pton(Data, Size);
    fuzz_ares_dns_rr_get_addr6(Data, Size);

    return 0;
}