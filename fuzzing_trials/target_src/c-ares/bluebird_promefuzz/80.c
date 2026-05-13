#include <stdint.h>
#include "stddef.h"
#include <string.h>
#include <stdlib.h>
#include "stdio.h"
#include <stdint.h>
#include "stddef.h"
#include <stdlib.h>
#include <string.h>
#include "stdio.h"
#include "ares.h"

static void cleanup_channel(ares_channel_t *channel) {
    if (channel) {
        ares_destroy(channel);
    }
}

static void fuzz_ares_set_servers_ports_csv(ares_channel_t *channel, const char *servers) {
    ares_set_servers_ports_csv(channel, servers);
}

static void fuzz_ares_get_servers(const ares_channel_t *channel) {
    struct ares_addr_node *servers = NULL;
    ares_get_servers(channel, &servers);
    if (servers) {
        ares_free_data(servers);
    }
}

static void fuzz_ares_set_servers_ports(ares_channel_t *channel, const struct ares_addr_port_node *servers) {
    ares_set_servers_ports(channel, servers);
}

static void fuzz_ares_set_servers_csv(ares_channel_t *channel, const char *servers) {
    ares_set_servers_csv(channel, servers);
}

static void fuzz_ares_set_servers(ares_channel_t *channel, const struct ares_addr_node *servers) {
    ares_set_servers(channel, servers);
}

static void fuzz_ares_get_servers_ports(const ares_channel_t *channel) {
    struct ares_addr_port_node *servers = NULL;
    ares_get_servers_ports(channel, &servers);
    if (servers) {

        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of ares_free_data
        ares_free_data((void *)"r");
        // End mutation: Producer.REPLACE_ARG_MUTATOR


    }
}

int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    ares_channel_t *channel = NULL;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    char *servers_csv = strndup((const char *)Data, Size);
    if (!servers_csv) {
        cleanup_channel(channel);
        return 0;
    }

    fuzz_ares_set_servers_ports_csv(channel, servers_csv);
    fuzz_ares_get_servers(channel);
    fuzz_ares_set_servers_ports(channel, NULL);
    fuzz_ares_set_servers_csv(channel, servers_csv);
    fuzz_ares_set_servers(channel, NULL);
    fuzz_ares_get_servers_ports(channel);

    free(servers_csv);
    cleanup_channel(channel);

    return 0;
}