#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_906(const uint8_t *Data, size_t Size) {
    // Initialize the Janet VM before using any Janet functions
    janet_init();

    // Prepare a null-terminated C string
    char *cstr = (char *)malloc(Size + 1);
    if (!cstr) return 0;
    memcpy(cstr, Data, Size);
    cstr[Size] = '\0';

    // Test janet_cstring
    JanetString jstr = janet_cstring(cstr);

    // Test janet_wrap_string
    Janet wrapped_jstr = janet_wrap_string(jstr);

    // Test janet_unwrap_string
    JanetString unwrapped_jstr = janet_unwrap_string(wrapped_jstr);

    // Test janet_to_string
    JanetString to_jstr = janet_to_string(wrapped_jstr);

    // Test janet_optstring
    Janet argv[1] = { wrapped_jstr };
    JanetString opt_jstr = janet_optstring(argv, 1, 0, jstr);

    // Test janet_cstrcmp
    int cmp_result = janet_cstrcmp(jstr, cstr);

    // Clean up
    free(cstr);

    // Write to a dummy file if needed
    write_dummy_file(Data, Size);

    // Deinitialize the Janet VM
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

    LLVMFuzzerTestOneInput_906(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
