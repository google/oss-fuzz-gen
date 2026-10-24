#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/hoextdown/src/buffer.h"

// Custom realloc function
void* custom_realloc(void* ptr, size_t size) {
    return realloc(ptr, size);
}

// Custom free function
void custom_free(void* ptr) {
    free(ptr);
}

// Fuzzer test function
int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    hoedown_buffer buffer;
    size_t buffer_size = 64; // Arbitrary non-zero size for initialization

    // Initialize the buffer
    hoedown_buffer_init(&buffer, buffer_size, custom_realloc, custom_free, custom_free);

    // The function hoedown_buffer_init does not return a value, so no further action is needed

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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
