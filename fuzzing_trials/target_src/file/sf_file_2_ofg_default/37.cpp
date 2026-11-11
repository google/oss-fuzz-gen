#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio> // Include the header for printf

extern "C" {
    #include <magic.h> // Wrap the C library include with extern "C"
}

extern "C" int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Ensure the data is not NULL and has a valid size
    if (data == NULL || size == 0) {
        printf("Invalid input data or size\n");
        return 0;
    }

    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        printf("Failed to initialize magic library\n");
        return 0;
    }

    if (magic_load(magic, NULL) != 0) {
        printf("Failed to load magic database: %s\n", magic_error(magic));
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, static_cast<const void*>(data), size);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result != NULL) {
        // Print the result for debugging purposes (can be removed in production)
        printf("Magic buffer result: %s\n", result);

        // Additional logic to ensure the result is used in a meaningful way
        // For example, checking if the result contains certain keywords
        if (strstr(result, "text") != NULL) {
            printf("Detected text file\n");
        } else if (strstr(result, "image") != NULL) {
            printf("Detected image file\n");
        } else {
            printf("Detected other file type\n");
        }

        // To ensure the fuzz target is effectively invoking the function under test,
        // let's modify the input slightly and call the function again.
        // This is just a simple example of how to mutate the input.
        uint8_t *mutated_data = (uint8_t *)malloc(size);
        if (mutated_data != NULL) {
            memcpy(mutated_data, data, size);
            mutated_data[0] ^= 0xFF; // Simple mutation: flip the first byte

            const char *mutated_result = magic_buffer(magic, static_cast<const void*>(mutated_data), size);
            if (mutated_result != NULL) {
                printf("Mutated magic buffer result: %s\n", mutated_result);
            }
            free(mutated_data);
        }
    } else {
        // If result is NULL, print an error message for debugging
        printf("Magic buffer returned NULL\n");
    }

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
