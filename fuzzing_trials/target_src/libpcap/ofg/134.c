#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include for memcpy
#include <pcap.h>

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    // Ensure the size is at least the size of an int
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int error_code;
    memcpy(&error_code, data, sizeof(int));

    // Call the function under test
    const char *error_message = pcap_strerror(error_code);

    // Use the error_message to avoid unused variable warning
    if (error_message) {
        // Do something with error_message if necessary
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

    LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
