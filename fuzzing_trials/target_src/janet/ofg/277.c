#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_277(const uint8_t *data, size_t size) {
    // Initialize Janet
    janet_init();

    // Create a JanetArray
    JanetArray *array = janet_array(0);

    // Ensure the array is not empty before popping
    if (size > 0) {
        for (size_t i = 0; i < size; i++) {
            // Convert each byte of data to a Janet integer and push to the array
            Janet value = janet_wrap_integer((int32_t)data[i]);
            janet_array_push(array, value);
        }

        // Pop an element from the array
        Janet popped_value = janet_array_pop(array);

        // Use the popped value to avoid unused variable warning
        (void)popped_value;
    }

    // Clean up Janet
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

    LLVMFuzzerTestOneInput_277(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
