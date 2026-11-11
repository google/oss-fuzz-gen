#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetString create_janet_string(const uint8_t *data, size_t size) {
    char *cstr = (char *)malloc(size + 1);
    if (!cstr) return NULL;
    memcpy(cstr, data, size);
    cstr[size] = '\0'; // Ensure null-termination
    JanetString jstr = janet_cstring(cstr);
    free(cstr);
    return jstr;
}

int LLVMFuzzerTestOneInput_843(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize Janet environment
    janet_init();

    // Step 1: Prepare input data
    JanetString jstr = create_janet_string(Data, Size);
    if (!jstr) {
        janet_deinit();
        return 0;
    }

    // Ensure Data is null-terminated for janet_cstrcmp
    char *cstr = (char *)malloc(Size + 1);
    if (!cstr) {
        janet_deinit();
        return 0;
    }
    memcpy(cstr, Data, Size);
    cstr[Size] = '\0'; // Ensure null-termination

    // Step 2: Test janet_wrap_string
    Janet wrapped = janet_wrap_string(jstr);

    // Step 3: Test janet_unwrap_string
    JanetString unwrapped = janet_unwrap_string(wrapped);

    // Step 4: Test janet_to_string
    JanetString converted = janet_to_string(wrapped);

    // Step 5: Test janet_optstring
    Janet argv[1] = { wrapped };
    JanetString optstr = janet_optstring(argv, 1, 0, jstr);

    // Step 6: Test janet_cstrcmp
    int cmp_result = janet_cstrcmp(jstr, cstr);

    // Clean up
    free(cstr);

    // Deinitialize Janet environment
    janet_deinit();

    // Clean up and return
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

    LLVMFuzzerTestOneInput_843(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
