#include <stddef.h>
#include <stdint.h>
#include <ares.h>
#include <string.h>
#include <arpa/nameser.h> // Include for ns_c_in and ns_t_a

// Define the LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    /* Initialize the c-ares library */
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        return 0;
    }

    /* Declare the channel at the top */
    ares_channel channel;

    /* Create a channel */
    if (ares_init(&channel) != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    /* Use the input data to perform a DNS query */
    if (size > 0) {
        char domain[256];
        size_t domain_length = size < 255 ? size : 255;
        memcpy(domain, data, domain_length);
        domain[domain_length] = '\0';

        ares_query(channel, domain, ns_c_in, ns_t_a, NULL, NULL);
    }

    /* Clean up the channel and library */
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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
