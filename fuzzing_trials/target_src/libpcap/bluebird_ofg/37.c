#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "pcap/pcap.h"

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Ensure that size is at least the size of an int
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int tstamp_type_val = *((const int *)data);

    // Call the function-under-test
    const char *description = pcap_tstamp_type_val_to_description(tstamp_type_val);

    // Do something with the result to prevent compiler optimizations from removing the call
    if (description != NULL) {
        // Just a simple operation to use the description
        volatile size_t desc_length = 0;
        while (description[desc_length] != '\0') {
            desc_length++;
        }
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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
