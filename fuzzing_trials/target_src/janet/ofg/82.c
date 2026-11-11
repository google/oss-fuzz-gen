#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern void janet_ev_write_string(JanetStream *, JanetString);

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Initialize Janet VM
    janet_init();

    // Create a JanetStream object
    JanetStream *stream = janet_stream(NULL, 0, 0);

    // Ensure the data is not empty to create a valid JanetString
    if (size > 0) {
        // Create a JanetString from the input data
        JanetString jstring = janet_string(data, size);

        // Call the function-under-test
        janet_ev_write_string(stream, jstring);
    }

    // Clean up Janet VM
    janet_deinit();

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

    LLVMFuzzerTestOneInput_82(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
