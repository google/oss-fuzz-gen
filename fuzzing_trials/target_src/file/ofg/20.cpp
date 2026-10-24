#include <stdint.h>
#include <stddef.h>
#include <magic.h>
#include <string.h>

extern "C" {
    #include <stdlib.h>
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Use a fixed and valid flag for better coverage
    if (magic_setflags(magic, MAGIC_MIME_TYPE) != 0) {
        magic_close(magic);
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Create a null-terminated string from the input data
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        magic_close(magic);
        return 0;
    }

    memcpy(input, data, size);
    input[size] = '\0';

    // Ensure the input is not empty and has meaningful content
    if (strlen(input) == 0) {
        free(input);
        magic_close(magic);
        return 0;
    }

    // Use the input string with magic_buffer to ensure code coverage
    const char *result = magic_buffer(magic, input, size);

    // Check the result to ensure it's not null, which indicates some processing
    if (result != NULL) {
        // Optionally, print or log the result for debugging purposes
        // printf("Magic result: %s\n", result);
    } else {
        // Handle error from magic_buffer
        // const char *error = magic_error(magic);
        // printf("Magic error: %s\n", error);
    }

    // Clean up
    free(input);
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
