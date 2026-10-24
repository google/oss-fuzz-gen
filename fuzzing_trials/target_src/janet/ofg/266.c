#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_266(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) + sizeof(int32_t) * 2 + sizeof(uint8_t)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Prepare the arguments for janet_optkeyword
    const Janet *janet_array = (const Janet *)data;
    int32_t n = *(int32_t *)(data + sizeof(Janet));
    int32_t def = *(int32_t *)(data + sizeof(Janet) + sizeof(int32_t));
    const uint8_t *keyword = data + sizeof(Janet) + sizeof(int32_t) * 2;

    // Ensure the keyword is null-terminated for safety
    uint8_t safe_keyword[256];
    size_t keyword_length = size - (sizeof(Janet) + sizeof(int32_t) * 2);
    if (keyword_length > 255) {
        keyword_length = 255;
    }
    memcpy(safe_keyword, keyword, keyword_length);
    safe_keyword[keyword_length] = '\0';

    // Validate and convert the Janet array
    JanetArray *array = janet_array_n(janet_array, size / sizeof(Janet));
    if (!array) {
        janet_deinit();
        return 0;
    }

    // Ensure the array has at least 'n' elements
    if (n < 0 || n >= array->count) {
        janet_deinit();
        return 0;
    }

    // Call the function-under-test
    JanetKeyword result = janet_optkeyword(array->data, n, def, safe_keyword);

    // Clean up the Janet environment
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

    LLVMFuzzerTestOneInput_266(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
