#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h> // Include the necessary header for fprintf and stderr

// Function-under-test declaration
void janet_clear_memory_236(uint8_t *buffer, size_t size);

// Fuzzing harness
int LLVMFuzzerTestOneInput_236(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Allocate a buffer to be cleared
    uint8_t *buffer = (uint8_t *)malloc(size);
    if (buffer == NULL) {
        return 0;
    }

    // Copy input data to the buffer
    memcpy(buffer, data, size);

    // Call the function-under-test
    janet_clear_memory_236(buffer, size);

    // Check if the buffer is cleared
    for (size_t i = 0; i < size; ++i) {
        if (buffer[i] != 0) {
            // If any byte is not zero, log the issue
            fprintf(stderr, "Buffer not cleared at index %zu\n", i);
            break;
        }
    }

    // Free the buffer
    free(buffer);

    return 0;
}

// Example implementation of janet_clear_memory_236
void janet_clear_memory_236(uint8_t *buffer, size_t size) {
    // Clear the memory (example implementation)
    memset(buffer, 0, size);
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

    LLVMFuzzerTestOneInput_236(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
