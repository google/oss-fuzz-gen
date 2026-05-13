#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    /* Declare variables */
    ares_channel channel = NULL;
    struct ares_options options;
    int optmask = 0;

    /* Initialize options with some default values */
    options.flags = ARES_FLAG_USEVC;
    options.timeout = 5000;
    options.tries = 3;
    options.ndots = 1;
    options.tcp_port = 53;
    options.udp_port = 53;

    /* Set optmask to include the options we are using */
    optmask = ARES_OPT_FLAGS | ARES_OPT_TIMEOUT | ARES_OPT_TRIES |
              ARES_OPT_NDOTS | ARES_OPT_TCP_PORT | ARES_OPT_UDP_PORT;

    /* Call the function-under-test */
    int result = ares_init_options(&channel, &options, optmask);

    /* Clean up the channel if it was initialized */
    if (result == ARES_SUCCESS && channel != NULL) {
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
