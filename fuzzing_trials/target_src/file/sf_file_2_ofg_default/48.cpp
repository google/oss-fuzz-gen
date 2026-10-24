#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>
#include <string.h> // Include the necessary header for memcpy

extern "C" {
    #include <stdio.h>
}

extern "C" int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        fprintf(stderr, "Failed to initialize magic set\n");
        return 0; // Exit if magic_set could not be created
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        fprintf(stderr, "Failed to load magic database: %s\n", magic_error(magic));
        magic_close(magic);
        return 0; // Exit if magic database could not be loaded
    }

    // Ensure the data is null-terminated to avoid undefined behavior
    uint8_t *null_terminated_data = (uint8_t *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        magic_close(magic);
        return 0; // Exit if memory allocation failed
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Call the function-under-test
    const char *result = magic_buffer(magic, null_terminated_data, size);

    // Check the result and perform additional operations
    if (result != NULL) {
        // For example, print the result to ensure it's being processed
        // In a real fuzzing environment, you might want to log or further analyze the result
        printf("Magic result: %s\n", result);
    } else {
        fprintf(stderr, "Magic buffer failed: %s\n", magic_error(magic));
    }

    // Perform any necessary cleanup
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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
