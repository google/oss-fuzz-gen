// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_library_init at ares_library_init.c:108:5 in ares.h
// ares_init_options at ares_init.c:238:5 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
// ares_getsock at ares_getsock.c:29:5 in ares.h
// ares_version at ares_version.c:29:13 in ares.h
// ares_strerror at ares_strerror.c:30:13 in ares.h
// ares_library_initialized at ares_library_init.c:161:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ares.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_53(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    int flags = *(int *)Data;
    Data += sizeof(int);
    Size -= sizeof(int);

    // Initialize library
    if (ares_library_init(flags) != ARES_SUCCESS) {
        return 0;
    }

    // Prepare options
    struct ares_options options;
    memset(&options, 0, sizeof(options));

    // Initialize channel
    ares_channel_t *channel = NULL;
    int optmask = ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;
    options.timeout = 5000; // 5 seconds
    options.tries = 3;
    int init_result = ares_init_options(&channel, &options, optmask);
    if (init_result != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    // Fuzz ares_getsock
    ares_socket_t socks[16];
    int numsocks = ares_getsock(channel, socks, 16);

    // Fuzz ares_version
    int version;
    const char *version_str = ares_version(&version);

    // Fuzz ares_strerror
    const char *error_str = ares_strerror(init_result);

    // Check library initialization state
    int lib_init_state = ares_library_initialized();

    // Perform cleanup
    ares_destroy(channel);
    ares_library_cleanup();

    // Write to dummy file
    write_dummy_file(Data, Size);

    return 0;
}