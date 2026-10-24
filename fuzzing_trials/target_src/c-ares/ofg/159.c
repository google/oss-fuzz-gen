#include <stddef.h>
#include <string.h>
#include <ares.h>
#include <arpa/nameser.h> // Include for C_IN and T_A

// Callback function to be used with ares_search
static void dummy_callback(void *arg, int status, int timeouts, const unsigned char *abuf, int alen) {
    (void)arg;      // Suppress unused parameter warning
    (void)status;   // Suppress unused parameter warning
    (void)timeouts; // Suppress unused parameter warning
    (void)abuf;     // Suppress unused parameter warning
    (void)alen;     // Suppress unused parameter warning
}

int LLVMFuzzerTestOneInput_159(const unsigned char *data, size_t size) { // Removed static keyword
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;
    int status;

    // Initialize ares library
    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Initialize ares channel
    status = ares_init_options(&channel, &options, optmask);
    if (status != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    // Ensure the name is null-terminated
    char name[256];
    size_t copy_size = size < sizeof(name) - 1 ? size : sizeof(name) - 1;
    memcpy(name, data, copy_size);
    name[copy_size] = '\0';

    // Define some arbitrary values for dnsclass and type
    int dnsclass = C_IN;
    int type = T_A;

    // Call the function-under-test
    ares_search(channel, name, dnsclass, type, dummy_callback, NULL);

    // Clean up
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

    LLVMFuzzerTestOneInput_159(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
