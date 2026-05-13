#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    /* Declare and initialize variables */
    ares_channel_t *channel = NULL;
    struct ares_options options;
    int optmask = 0;

    /* Ensure the size of data is sufficient to fill options */
    if (size < sizeof(struct ares_options)) {
        return 0;
    }

    /* Copy data into options */
    memcpy(&options, data, sizeof(struct ares_options));

    /* Use remaining data to set optmask */
    if (size > sizeof(struct ares_options)) {
        optmask = (int)data[sizeof(struct ares_options)];
    }

    /* Call the function-under-test */
    int result = ares_init_options(&channel, &options, optmask);

    /* Clean up */
    if (result == ARES_SUCCESS) {
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
