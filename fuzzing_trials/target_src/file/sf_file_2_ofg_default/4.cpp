#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0; // Return early if data is null or size is zero
    }

    struct magic_set *magic;
    const char *result;

    // Initialize a magic_set object
    magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Ensure the data is null-terminated for safety
    uint8_t *null_terminated_data = (uint8_t *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        magic_close(magic);
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    result = magic_buffer(magic, null_terminated_data, size);

    // Check the result to ensure the function is being exercised
    if (result != NULL) {
        // Optionally, you can print the result or perform other checks
        // printf("Magic result: %s\n", result);
    } else {
        // If result is NULL, consider logging or handling this case
        // printf("Magic buffer returned NULL\n");
    }

    // Clean up
    free(null_terminated_data);
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
