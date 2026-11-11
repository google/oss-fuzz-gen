#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <janet.h>

// Fuzzing harness for janet_buffer_push_cstring
int LLVMFuzzerTestOneInput_379(const uint8_t *data, size_t size) {
    // Ensure that the size is at least 1 to create a valid null-terminated string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for a JanetBuffer
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10); // Initialize with a default size

    // Allocate memory for a null-terminated string
    char *cstring = (char *)malloc(size + 1);
    if (!cstring) {
        return 0;
    }

    // Copy data into the string and null-terminate it
    memcpy(cstring, data, size);
    cstring[size] = '\0';

    // Call the function-under-test
    janet_buffer_push_cstring(&buffer, cstring);

    // Clean up
    free(cstring);
    janet_buffer_deinit(&buffer);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_379(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
