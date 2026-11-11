#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_294(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract an int32_t
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Initialize a JanetBuffer instance
    JanetBuffer buffer;
    
    // Extract an int32_t from the input data
    int32_t capacity = *((int32_t *)data);

    // Call the function-under-test
    JanetBuffer *result = janet_buffer_init(&buffer, capacity);

    // Optionally, perform any additional operations on the result
    // For example, you could check if the result is not NULL
    if (result == NULL) {
        return 0;
    }

    // Clean up if necessary
    // Janet buffer does not require explicit cleanup in this context

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_294(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
