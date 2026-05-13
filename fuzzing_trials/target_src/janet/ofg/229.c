#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_229(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < 1) {
        return 0;
    }

    // Initialize Janet environment
    janet_init();

    // Create a Janet value from the data
    Janet janet_value = janet_wrap_string(janet_string(data, size));

    // Create a null-terminated string from the data
    char *cstr = (char *)malloc(size + 1);
    if (!cstr) {
        janet_deinit();
        return 0;
    }
    memcpy(cstr, data, size);
    cstr[size] = '\0';

    // Call the function-under-test
    int result = janet_keyeq(janet_value, cstr);

    // Clean up
    free(cstr);
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

    LLVMFuzzerTestOneInput_229(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
