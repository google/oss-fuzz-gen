#include <stdint.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>

extern "C" {
    // Include necessary headers and declare the function-under-test
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Initialize the magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // If magic_open fails, exit early
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, exit early
    }

    // Ensure we have at least 4 bytes to form an integer
    if (size < sizeof(int)) {
        magic_close(magic);
        return 0; // Exit early if not enough data
    }

    // Use the first 4 bytes of data as an integer
    int descriptor = *(reinterpret_cast<const int*>(data));

    // Instead of checking if descriptor is valid (non-negative),
    // we will attempt to use it directly to ensure coverage
    // Call the function-under-test
    const char *result = magic_descriptor(magic, descriptor);

    // Check if the result is not null to ensure the function is utilized
    if (result != NULL) {
        // Process the result if needed, e.g., print or log it
        // For fuzzing, we might just ensure it's accessed
        volatile size_t result_length = strlen(result);
        (void)result_length; // Avoid unused variable warning
    } else {
        // If result is null, attempt to use another descriptor
        // This can be a simple retry mechanism with a different descriptor
        descriptor = 0; // Reset descriptor to a common valid value
        result = magic_descriptor(magic, descriptor);
        if (result != NULL) {
            volatile size_t result_length = strlen(result);
            (void)result_length; // Avoid unused variable warning
        }
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
