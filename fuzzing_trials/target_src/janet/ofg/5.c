#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a Janet object from the input data
    Janet janet_obj;
    if (size > 0) {
        // Use the first byte of data to determine the type of Janet object
        switch (data[0] % 5) {
            case 0:
                // Integer
                janet_obj = janet_wrap_integer((int32_t)data[0]);
                break;
            case 1:
                // Number
                janet_obj = janet_wrap_number((double)data[0]);
                break;
            case 2:
                // Boolean
                janet_obj = janet_wrap_boolean(data[0] % 2);
                break;
            case 3:
                // String
                janet_obj = janet_wrap_string(janet_string(data, size));
                break;
            case 4: {
                // Buffer
                JanetBuffer *buffer = janet_buffer(size);
                janet_buffer_push_bytes(buffer, data, size);
                janet_obj = janet_wrap_buffer(buffer);
                break;
            }
            default:
                // Default to nil
                janet_obj = janet_wrap_nil();
                break;
        }
    } else {
        // Default to nil if size is zero
        janet_obj = janet_wrap_nil();
    }

    // Call the function-under-test
    int result = janet_checksize(janet_obj);

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_5(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
