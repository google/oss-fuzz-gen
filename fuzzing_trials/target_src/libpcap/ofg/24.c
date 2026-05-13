#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }

    int datalink_val;
    // Copy the first sizeof(int) bytes from data into datalink_val
    memcpy(&datalink_val, data, sizeof(int));

    // Call the function-under-test
    const char *description = pcap_datalink_val_to_description(datalink_val);

    // Use the description in some way to prevent optimization out
    if (description != NULL) {
        // Print the description length to ensure it's used
        volatile size_t desc_length = strlen(description);
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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
