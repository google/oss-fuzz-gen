extern "C" {
    #include <magic.h>
    #include <stdio.h> // Include the standard I/O library for printf
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Initialize a magic_set object
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        fprintf(stderr, "Failed to initialize magic library\n");
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        fprintf(stderr, "Failed to load magic database: %s\n", magic_error(magic));
        magic_close(magic);
        return 0;
    }

    // Ensure the input data is meaningful for processing
    if (size == 0 || data == NULL) {
        magic_close(magic);
        return 0;
    }

    // Call the function-under-test
    const char *result = magic_buffer(magic, (const void *)data, size);

    // Ensure result is not used in a way that could cause a crash
    if (result != NULL) {
        // For fuzzing purposes, print the result to ensure it's being used
        // This can help in identifying different paths taken during fuzzing
        printf("Magic result: %s\n", result);
    } else {
        fprintf(stderr, "magic_buffer failed: %s\n", magic_error(magic));
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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
