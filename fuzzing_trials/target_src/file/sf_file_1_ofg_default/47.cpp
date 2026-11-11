#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>  // Include for printf

extern "C" {
    // Since the project under test is written in C, ensure to wrap C headers and functions in extern "C"
    // This is already done correctly in the original code.
}

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0; // If magic_open fails, exit early
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0; // If magic_load fails, exit early
    }

    // Ensure size is non-zero and data is not null
    if (size > 0 && data != NULL) {
        // Call the function-under-test using magic_buffer
        const char *result = magic_buffer(ms, data, size);

        // Use the result in some way to prevent optimization out
        if (result != NULL) {
            // Print the result to ensure it is being used
            printf("Magic buffer result: %s\n", result);
        }
    } else {
        // If size is zero or data is null, provide a default non-null input to test
        const char *default_data = "default";
        const char *result = magic_buffer(ms, (const uint8_t *)default_data, strlen(default_data));

        if (result != NULL) {
            // Print the result to ensure it is being used
            printf("Magic buffer result with default data: %s\n", result);
        }
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
