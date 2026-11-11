#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>

extern "C" {
    const char * magic_buffer(struct magic_set *, const void *, size_t);
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Check if the input size is zero and return early if it is
    if (size == 0) {
        return 0;
    }

    // Create a magic_set instance
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, (const void *)data, size);

    // Check the result (not NULL)
    if (result != NULL) {
        // Optionally, you can print or log the result for debugging purposes
        // printf("Magic Buffer Result: %s\n", result);
        
        // Use the result in a way that affects code coverage
        volatile int dummy = 0;
        for (size_t i = 0; result[i] != '\0'; ++i) {
            dummy += result[i];  // Access each character to ensure the result is used
        }
    } else {
        // Handle the case where result is NULL, which can also be useful for fuzzing
        volatile int dummy = 0;
        dummy += 1;  // Increment to ensure this branch is considered
    }

    // Clean up
    magic_close(magic);

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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
