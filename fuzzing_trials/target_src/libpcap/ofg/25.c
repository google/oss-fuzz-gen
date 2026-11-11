#include <stdint.h>
#include <stddef.h>
#include <pcap.h> // Include the necessary header for pcap_datalink_val_to_description

// Remove the extern "C" linkage specification for C++ compatibility
int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Ensure there's enough data to form an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int datalink_type = *(const int *)data;

    // Call the function-under-test
    const char *description = pcap_datalink_val_to_description(datalink_type);

    // Optionally, you can use the description for further operations
    // For example, you could print it or perform other checks
    // Ensure description is not null before using it
    if (description != NULL) {
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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
