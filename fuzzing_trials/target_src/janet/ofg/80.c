#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Initialize Janet VM
    janet_init();

    // Ensure size is sufficient to create a Janet string
    if (size == 0) {
        return 0;
    }

    // Create a Janet string from the input data
    JanetString janetStr = janet_string(data, size);

    // Wrap the Janet string into a Janet type
    Janet janetValue = janet_wrap_string(janetStr);

    // Call the function-under-test
    JanetStruct result = janet_unwrap_struct(janetValue);

    // Cleanup Janet VM
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

    LLVMFuzzerTestOneInput_80(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
