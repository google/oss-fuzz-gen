#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "ares.h"

static void dummy_host_callback(void *arg, int status, int timeouts, const struct hostent *host) {
    // Dummy callback function for ares_gethostbyname
}

static void dummy_server_state_callback(const char *server, ares_bool_t up, int errcode, void *user_data) {
    // Dummy server state callback function
}

int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    ares_channel_t *channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // ares_get_servers_csv
    char *servers_csv = ares_get_servers_csv(channel);
    if (servers_csv != NULL) {
        ares_free_string(servers_csv);
    }

    // ares_set_server_state_callback
    ares_set_server_state_callback(channel, dummy_server_state_callback, NULL);

    // Prepare a hostname from input data
    char hostname[256];
    size_t hostname_len = Size < 255 ? Size : 255;
    memcpy(hostname, Data, hostname_len);
    hostname[hostname_len] = '\0';

    // ares_gethostbyname
    ares_gethostbyname(channel, hostname, AF_INET, dummy_host_callback, NULL);

    // Cleanup
    ares_destroy(channel);

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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
