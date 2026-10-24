#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
}

extern "C" int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    struct magic_set *ms;

    // Initialize a magic_set object with more comprehensive flags
    ms = magic_open(MAGIC_NONE | MAGIC_MIME_TYPE | MAGIC_CONTINUE);
    if (ms == NULL) {
        return 0; // If initialization fails, exit early
    }

    // Load default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0; // If loading fails, exit early
    }

    // Ensure data is not empty and has meaningful content
    if (size == 0 || data == NULL) {
        magic_close(ms);
        return 0;
    }

    // To increase code coverage, ensure that the data is null-terminated
    uint8_t *null_terminated_data = (uint8_t *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        magic_close(ms);
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    const char *result = magic_buffer(ms, null_terminated_data, size);

    // Check if result is not NULL to ensure function is utilized
    if (result != NULL && strlen(result) > 0) {
        // Optionally, perform some operation with the result
        // For example, print it or log it (not recommended in fuzzing due to performance)
        // printf("Magic result: %s\n", result);
    }

    // Clean up
    free(null_terminated_data);
    magic_close(ms);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
