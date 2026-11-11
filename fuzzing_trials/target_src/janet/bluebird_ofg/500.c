#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h" // Assuming the Janet library provides this header

int LLVMFuzzerTestOneInput_500(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a JanetBuffer
    JanetBuffer *buffer = janet_buffer(size);

    // Ensure the data is null-terminated for string operations
    uint8_t *null_terminated_data = (uint8_t *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        janet_deinit();
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Convert the null-terminated data to a Janet string
    JanetString janet_str = janet_string(null_terminated_data, size);

    // Call the function-under-test with a valid Janet string
    janet_buffer_push_string(buffer, janet_str);

    // Clean up
    free(null_terminated_data);
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

    LLVMFuzzerTestOneInput_500(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
