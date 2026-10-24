// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_init_options at ares_init.c:238:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_init_options at ares_init.c:238:5 in ares.h
// ares_set_servers_csv at ares_update_servers.c:1304:5 in ares.h
// ares_set_sortlist at ares_init.c:581:5 in ares.h
// ares_dup at ares_init.c:455:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_save_options at ares_options.c:83:5 in ares.h
// ares_destroy_options at ares_options.c:37:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>

static void write_dummy_file(const char *filename, const uint8_t *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    ares_channel_t *channel = NULL;
    ares_channel_t *dup_channel = NULL;
    struct ares_options options;
    int optmask = 0;
    int status;

    // Initialize options with dummy values
    memset(&options, 0, sizeof(options));
    options.timeout = 5000;  // 5 seconds timeout

    // Write data to dummy file if needed
    write_dummy_file("./dummy_file", Data, Size);

    // 1. Initialize ares with options
    status = ares_init_options(&channel, &options, optmask);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // 2. Destroy the initialized channel
    ares_destroy(channel);

    // 3. Re-initialize ares with options
    status = ares_init_options(&channel, &options, optmask);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // 4. Set servers using CSV format
    ares_set_servers_csv(channel, "127.0.0.1:53,8.8.8.8:53");

    // 5. Set sortlist
    ares_set_sortlist(channel, "127.0.0.0/8");

    // 6. Duplicate the channel
    status = ares_dup(&dup_channel, channel);
    if (status != ARES_SUCCESS) {
        ares_destroy(channel);
        return 0;
    }

    // 7. Save options
    struct ares_options saved_options;
    int saved_optmask;
    status = ares_save_options(channel, &saved_options, &saved_optmask);
    if (status == ARES_SUCCESS) {
        // 8. Destroy saved options
        ares_destroy_options(&saved_options);
    }

    // 9. Destroy duplicated channel
    ares_destroy(dup_channel);

    // 10. Destroy original channel
    ares_destroy(channel);

    return 0;
}