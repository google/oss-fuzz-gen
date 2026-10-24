#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned int)) {
        return 0; /* Not enough data to extract an unsigned int */
    }

    ares_channel channel;
    int status;
    struct ares_options options;
    int optmask = 0;

    /* Initialize the ares library */
    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    /* Initialize the ares channel */
    status = ares_init_options(&channel, &options, optmask);
    if (status != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    /* Extract an unsigned int from the data */
    unsigned int local_ip;
    memcpy(&local_ip, data, sizeof(unsigned int));

    /* Call the function-under-test */
    ares_set_local_ip4(&channel, local_ip);

    /* Clean up */
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

    LLVMFuzzerTestOneInput_104(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
