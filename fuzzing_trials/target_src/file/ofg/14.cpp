#include <stdint.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Check if the input data is not empty and has a reasonable size
    if (size == 0 || size > 1024) { // Limit size for practical reasons
        return 0;
    }

    // Initialize variables
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0; // If magic_open fails, exit early
    }

    // Load a magic database file
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0; // If magic_load fails, exit early
    }

    // Call the function-under-test with the provided data
    const char *result = magic_buffer(ms, data, size);
    if (result == NULL) {
        magic_close(ms);
        return 0; // If magic_buffer fails, exit early
    }

    // Process the result to ensure it is used
    for (size_t i = 0; result[i] != '\0'; ++i) {
        volatile int dummy = 0;
        dummy += result[i]; // Use the result in some way to prevent optimization out
    }

    // Additional processing to ensure the result is utilized
    if (result[0] != '\0') {
        volatile int check = 1;
        check += result[0]; // Further ensure the result is used
    }

    // Check for specific patterns or types in the result
    if (strstr(result, "text") != NULL) {
        volatile int text_found = 1;
        text_found += 1; // Example of further processing based on result content
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
