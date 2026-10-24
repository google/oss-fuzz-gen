#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ares.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void dummy_callback(void *arg, int status, int timeouts, const struct hostent *host) {
    // Dummy callback function
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    ares_channel_t *channel;
    int status;

    // Initialize the ares library
    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Initialize the channel
    status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    // Prepare server addresses
    struct ares_addr_node server;
    memset(&server, 0, sizeof(server));
    server.family = AF_INET;
    if (Size >= sizeof(struct in_addr)) {
        memcpy(&server.addr.addr4, Data, sizeof(struct in_addr));
    }

    // Call ares_set_servers
    ares_set_servers(channel, &server);

    // Prepare a hostname from input data
    char hostname[256];
    size_t hostname_len = (Size < 255) ? Size : 255;
    memcpy(hostname, Data, hostname_len);
    hostname[hostname_len] = '\0';

    // Call ares_gethostbyname
    ares_gethostbyname(channel, hostname, AF_INET, dummy_callback, NULL);

    // Cancel all queries
    ares_cancel(channel);

    // Cleanup
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
