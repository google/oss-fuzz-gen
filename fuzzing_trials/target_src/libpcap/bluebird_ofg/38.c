#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "pcap/pcap.h"

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer value from the input data
    int tstamp_type_val = *(const int *)data;

    // Call the function-under-test
    const char *result = pcap_tstamp_type_val_to_name(tstamp_type_val);

    // Use the result in some way to prevent optimizations from removing the call
    if (result != NULL) {
        // Print the result to demonstrate usage
        printf("Timestamp type name: %s\n", result);
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

    LLVMFuzzerTestOneInput_38(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
