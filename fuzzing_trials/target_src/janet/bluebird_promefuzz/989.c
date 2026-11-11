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

int LLVMFuzzerTestOneInput_989(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(int32_t)) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    write_dummy_file(Data, Size);

    Janet *argv = (Janet *) Data;
    int32_t n = *(int32_t *)(Data + sizeof(Janet));

    // Ensure n is within bounds of the argv array
    int32_t argc = (Size / sizeof(Janet)) - 1;
    if (n < 0 || n >= argc) {
        janet_deinit();
        return 0;
    }

    // Fuzz janet_getstruct
    JanetStruct js = NULL;
    if (n >= 0 && n < argc) {
        js = janet_getstruct(argv, n);
    }

    // Fuzz janet_struct_begin
    int32_t count = n % 1024; // Limit to a reasonable count
    JanetKV *kv = janet_struct_begin(count);

    // Fuzz janet_struct_end
    JanetStruct js_end = NULL;
    if (kv) {
        js_end = janet_struct_end(kv);
    }

    // Fuzz janet_struct_get_ex
    Janet key = argv[0]; // Use the first element as a key
    JanetStruct which = NULL;
    Janet value = janet_struct_get_ex(js, key, &which);

    // Fuzz janet_struct_find
    const JanetKV *found_kv = janet_struct_find(js, key);

    // Fuzz janet_optstruct
    JanetStruct dflt = js_end; // Use the ended struct as default
    JanetStruct opt_struct = janet_optstruct(argv, argc, n / 2, dflt);

    // Deinitialize Janet VM
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

    LLVMFuzzerTestOneInput_989(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
