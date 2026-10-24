#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <janet.h> // Assuming the Janet library provides this header

int LLVMFuzzerTestOneInput_378(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to be used as a C string
    char *cstring = (char *)malloc(size + 1);
    if (cstring == NULL) {
        return 0;
    }
    memcpy(cstring, data, size);
    cstring[size] = '\0';

    // Initialize a JanetBuffer
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10); // Initializing with a small size for testing

    // Call the function-under-test
    janet_buffer_push_cstring(&buffer, cstring);

    // Clean up
    janet_buffer_deinit(&buffer);
    free(cstring);

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

    LLVMFuzzerTestOneInput_378(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
