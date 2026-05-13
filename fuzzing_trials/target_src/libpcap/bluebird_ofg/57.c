#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "pcap/pcap.h"

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }

    // Interpret the first few bytes of data as an integer for the status code
    int status_code = *(const int *)data;

    // Call the function-under-test
    const char *status_str = pcap_statustostr(status_code);

    // Use the result in some way to prevent it from being optimized out
    if (status_str != NULL) {
        // For example, we could print it, but in fuzzing, we typically don't need to do anything
        // with the result other than ensuring the function is called.
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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
