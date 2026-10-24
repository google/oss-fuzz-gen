#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ares.h"

static int initialize_channel(ares_channel_t **channelptr) {
    struct ares_options options;
    memset(&options, 0, sizeof(options));
    int optmask = 0; // No specific options set
    return ares_init_options(channelptr, &options, optmask);
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    ares_channel_t *channel = NULL;
    int status = initialize_channel(&channel);

    if (status == ARES_SUCCESS) {
        ares_destroy(channel);
        status = initialize_channel(&channel);
    }

    if (status == ARES_SUCCESS) {
        char *servers_csv = "8.8.8.8,8.8.4.4";
        ares_set_servers_csv(channel, servers_csv);

        char *sortlist = "192.168.1.0/24";
        ares_set_sortlist(channel, sortlist);

        ares_channel_t *dup_channel = NULL;
        if (ares_dup(&dup_channel, channel) == ARES_SUCCESS) {
            struct ares_options saved_options;
            int optmask;
            if (ares_save_options(dup_channel, &saved_options, &optmask) == ARES_SUCCESS) {
                ares_destroy_options(&saved_options);
            }
            ares_destroy(dup_channel);
        }

        // Remove the invalid call to ares_destroy_options with NULL
        ares_destroy(channel);
    }

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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
