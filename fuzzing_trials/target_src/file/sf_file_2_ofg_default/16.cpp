#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>

extern "C" {
    // Function-under-test
    const char * magic_buffer(struct magic_set *, const void *, size_t);
    const char * magic_error(struct magic_set *);
    int magic_load(struct magic_set *, const char *);
    void magic_close(struct magic_set *);
    struct magic_set *magic_open(int);
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Check if the input size is valid
    if (size == 0) {
        return 0; // Do not proceed with empty input
    }

    // Initialize a magic_set object with different flags to explore more code paths
    struct magic_set *magic = magic_open(MAGIC_NONE | MAGIC_MIME | MAGIC_CONTINUE);
    if (magic == NULL) {
        return 0; // If magic_open fails, exit early
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, exit early
    }

    // Ensure the input is not null and has a minimum size if required by the function
    if (data == NULL || size < 1) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test with valid input
    const char *result = magic_buffer(magic, data, size);

    // Optionally, check the result to ensure it's being utilized
    if (result != NULL) {
        // Do something with the result, e.g., log it or further process
        // For fuzzing, we can just ensure it's accessed
        volatile const char *volatile_result = result;
        (void)volatile_result; // Prevent compiler optimizations
    } else {
        // If result is NULL, it might indicate an issue with processing
        // We can attempt to log an error or handle it accordingly
        const char *error_message = magic_error(magic);
        if (error_message != NULL) {
            // Log or handle the error message
            volatile const char *volatile_error = error_message;
            (void)volatile_error; // Prevent compiler optimizations
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
