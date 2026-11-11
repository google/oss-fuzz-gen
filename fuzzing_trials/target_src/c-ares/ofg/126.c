#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    ares_channel channel;
    struct ares_options options;
    int optmask = 0;

    /* Initialize the ares library */
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        return 0;
    }

    /* Initialize options with some default values */
    options.flags = ARES_FLAG_USEVC;
    options.timeout = 5000; /* 5 seconds timeout */
    options.tries = 3; /* Number of tries */
    optmask = ARES_OPT_FLAGS | ARES_OPT_TIMEOUT | ARES_OPT_TRIES;

    /* Initialize the channel with options */
    if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    /* Call the function under test */
    char *servers_csv = ares_get_servers_csv(channel);

    /* Free the allocated memory */
    if (servers_csv) {
        ares_free_data(servers_csv);
    }

    /* Destroy the channel and cleanup */
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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
