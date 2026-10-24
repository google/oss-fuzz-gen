#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>

extern "C" {
    #include <stdio.h>
    #include <string.h> // Include string.h for memcpy
}

extern "C" int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Check if the input data is non-empty
    if (data == NULL || size == 0) {
        return 0; // Exit early if input is not valid
    }

    // Initialize a magic_set object
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // If magic_open fails, exit the fuzzer
    }

    // Load default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If magic_load fails, exit the fuzzer
    }

    // Create a buffer with a null terminator to ensure it's valid C-string
    char *buffer = (char *)malloc(size + 1);
    if (buffer == NULL) {
        magic_close(magic);
        return 0; // Exit if memory allocation fails
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0'; // Null-terminate the buffer

    // Call the function-under-test
    const char *result = magic_buffer(magic, buffer, size);
    if (result != NULL) {
        // Print the result to verify it is being processed
        printf("Magic result: %s\n", result);
    } else {
        // If result is NULL, it means the magic_buffer did not recognize the input
        // We can return a non-zero value to indicate this case, which may help in coverage
        magic_close(magic);
        free(buffer);
        return 1;
    }

    // Cleanup
    magic_close(magic);
    free(buffer);

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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
