// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_init at ares_init.c:67:5 in ares.h
// ares_dup at ares_init.c:455:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_set_local_ip4 at ares_init.c:546:6 in ares.h
// ares_set_local_ip6 at ares_init.c:557:6 in ares.h
// ares_set_local_dev at ares_init.c:568:6 in ares.h
// ares_query_dnsrec at ares_query.c:115:15 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_query at ares_query.c:133:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>
#include <arpa/nameser.h>

static void dns_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // Dummy callback function for ares_query
}

static void dnsrec_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
    // Dummy callback function for ares_query_dnsrec
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    ares_channel_t *channel = NULL;
    ares_channel_t *dup_channel = NULL;
    unsigned int local_ip4;
    unsigned char local_ip6[16];
    char local_dev_name[32];
    unsigned short qid;
    int status;

    if (Size < sizeof(local_ip4) + sizeof(local_ip6) + sizeof(local_dev_name)) {
        return 0;
    }

    // Initialize local_ip4, local_ip6, and local_dev_name
    memcpy(&local_ip4, Data, sizeof(local_ip4));
    Data += sizeof(local_ip4);
    Size -= sizeof(local_ip4);

    memcpy(local_ip6, Data, sizeof(local_ip6));
    Data += sizeof(local_ip6);
    Size -= sizeof(local_ip6);

    memcpy(local_dev_name, Data, sizeof(local_dev_name) - 1);
    local_dev_name[sizeof(local_dev_name) - 1] = '\0';
    Data += sizeof(local_dev_name) - 1;
    Size -= sizeof(local_dev_name) - 1;

    // Create a channel
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Duplicate the channel
    if (ares_dup(&dup_channel, channel) != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // Set local IPv4 address
    ares_set_local_ip4(dup_channel, local_ip4);

    // Set local IPv6 address
    ares_set_local_ip6(dup_channel, local_ip6);

    // Set local device name
    ares_set_local_dev(dup_channel, local_dev_name);

    // Perform a DNS query with ares_query_dnsrec
    status = ares_query_dnsrec(dup_channel, "example.com", ns_c_in, ns_t_a, dnsrec_callback, NULL, &qid);
    if (status != ARES_SUCCESS) {
        ares_destroy(dup_channel);
        ares_destroy(channel);
        return 0;
    }

    // Perform a DNS query with ares_query (deprecated)
    ares_query(dup_channel, "example.com", ns_c_in, ns_t_a, dns_callback, NULL);

    // Cleanup
    ares_destroy(dup_channel);
    ares_destroy(channel);

    return 0;
}