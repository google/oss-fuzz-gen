#include <stdint.h>
#include <stddef.h>
#include <magic.h>  // Include the magic header for function and struct definitions
#include <cstdio>   // Include the C++ header for printf
#include <cstdlib>  // Include for random number generation

extern "C" {
    // Ensure that the function is linked correctly with C code
    const char * magic_buffer(struct magic_set *, const void *, size_t);
    struct magic_set *magic_open(int);
    int magic_load(struct magic_set *, const char *);
    void magic_close(struct magic_set *);
}

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Create a magic_set object using the magic_open function
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // Exit if magic_open fails
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // Exit if magic_load fails
    }

    // Check if the size is greater than 0 to ensure non-null input
    if (size > 0) {
        // Call the function-under-test
        const char *result = magic_buffer(magic, data, size);
        if (result != NULL) {
            // Process the result to ensure the function is utilized
            // For example, log the result or perform a simple operation
            // This helps in ensuring that the function is being tested effectively
            // Print the result to ensure it is being processed
            printf("Magic Buffer Result: %s\n", result);
        } else {
            // Handle the case where the result is NULL
            // This could indicate an error or a non-recognizable input
            printf("Magic Buffer returned NULL for the given input.\n");
        }
    } else {
        // Handle the case where the input size is zero
        printf("Input size is zero, skipping magic_buffer call.\n");
    }

    // Ensure to close the magic_set object to free resources
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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
