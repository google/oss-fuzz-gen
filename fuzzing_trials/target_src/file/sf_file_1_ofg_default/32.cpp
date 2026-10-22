#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <magic.h>

extern "C" {
    // Forward declaration of the function-under-test
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Initialize a magic_set structure
    struct magic_set *ms = magic_open(MAGIC_NONE);
    if (ms == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(ms, NULL) != 0) {
        magic_close(ms);
        return 0;
    }

    // Ensure the size is sufficient for an integer
    if (size < sizeof(int)) {
        magic_close(ms);
        return 0;
    }

    // Copy the first part of the data into an integer
    int descriptor;
    memcpy(&descriptor, data, sizeof(int));

    // Use the entire data to influence the descriptor value
    // Increase the range to a higher value to explore more cases
    descriptor = abs(descriptor) % 4096; // Assuming 4096 is a reasonable maximum for valid descriptors

    // Call the function-under-test
    const char *result = magic_descriptor(ms, descriptor);
    
    // Check if the result is NULL and handle it
    if (result != NULL) {
        printf("Magic descriptor: %s\n", result);
    } else {
        // If result is NULL, try calling magic_error to get more information
        const char *error = magic_error(ms);
        if (error != NULL) {
            printf("Magic error: %s\n", error);
        } else {
            printf("Magic descriptor is NULL for descriptor: %d\n", descriptor);
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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
