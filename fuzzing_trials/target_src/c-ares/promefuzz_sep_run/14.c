// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_expand_name at ares_expand_name.c:84:5 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_expand_string at ares_expand_string.c:93:5 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_fds at ares_fds.c:30:5 in ares.h
// ares_library_init at ares_library_init.c:108:5 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <sys/select.h>

static void fuzz_ares_destroy(ares_channel_t *channel) {
    if (channel) {
        ares_destroy(channel);
    }
}

static void fuzz_ares_expand_name(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data

    const unsigned char *encoded = Data;
    const unsigned char *abuf = Data;
    int alen = (int)Size;
    char *s = NULL;
    long enclen = 0;
    
    int result = ares_expand_name(encoded, abuf, alen, &s, &enclen);
    if (result == ARES_SUCCESS) {
        ares_free_string(s);
    }
}

static void fuzz_ares_expand_string(const uint8_t *Data, size_t Size) {
    if (Size < 2) return; // Ensure there's enough data

    const unsigned char *encoded = Data;
    const unsigned char *abuf = Data;
    int alen = (int)Size;
    unsigned char *s = NULL;
    long enclen = 0;
    
    int result = ares_expand_string(encoded, abuf, alen, &s, &enclen);
    if (result == ARES_SUCCESS) {
        ares_free_string(s);
    }
}

static void fuzz_ares_fds(ares_channel_t *channel) {
    if (channel) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        ares_fds(channel, &read_fds, &write_fds);
    }
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    ares_channel_t *channel = NULL;
    ares_library_init(ARES_LIB_INIT_ALL);

    fuzz_ares_destroy(channel);
    fuzz_ares_expand_name(Data, Size);
    fuzz_ares_expand_string(Data, Size);
    fuzz_ares_fds(channel);

    ares_library_cleanup();
    return 0;
}