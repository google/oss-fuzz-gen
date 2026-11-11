#include <stdint.h>
#include <stddef.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }

    int dlt_value;
    // Copy the first few bytes of data to an integer
    // Ensure that the data is not null and is big enough to be an int
    dlt_value = *(const int *)data;

    // Call the function-under-test
    const char *description = pcap_datalink_val_to_description_or_dlt(dlt_value);

    // Use the description in some way to avoid compiler optimizations
    if (description != NULL) {
        // Print the description (optional, for debugging purposes)
        // printf("Description: %s\n", description);
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

    LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
