#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void initialize_janet() {
    janet_init();
}

static void cleanup_janet() {
    janet_deinit();
}

int LLVMFuzzerTestOneInput_911(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    initialize_janet();

    // Fuzz janet_bytes_view
    Janet janet_value;
    const uint8_t *byte_data = NULL;
    int32_t length = 0;
    if (janet_checktype(janet_value, JANET_STRING) ||
        janet_checktype(janet_value, JANET_SYMBOL) ||
        janet_checktype(janet_value, JANET_KEYWORD) ||
        janet_checktype(janet_value, JANET_BUFFER) ||
        janet_checktype(janet_value, JANET_ABSTRACT)) {
        
        janet_bytes_view(janet_value, &byte_data, &length);
    }

    // Fuzz janet_unwrap_string
    if (janet_checktype(janet_value, JANET_STRING)) {
        JanetString janet_str = janet_unwrap_string(janet_value);
    }

    // Fuzz janet_string_begin
    int32_t str_length = (int32_t)(Data[0] % 256); // Use first byte as length
    uint8_t *new_str = janet_string_begin(str_length);

    // Fuzz janet_string
    if (Size > 1) {
        JanetString created_string = janet_string(Data, (int32_t)(Size - 1));
    }

    // Fuzz janet_string_end
    if (new_str) {
        JanetString ended_string = janet_string_end(new_str);
    }

    // Fuzz janet_to_string
    if (janet_checktype(janet_value, JANET_STRING) ||
        janet_checktype(janet_value, JANET_SYMBOL) ||
        janet_checktype(janet_value, JANET_KEYWORD) ||
        janet_checktype(janet_value, JANET_BUFFER) ||
        janet_checktype(janet_value, JANET_ABSTRACT)) {
        
        JanetString converted_string = janet_to_string(janet_value);
    }

    cleanup_janet();
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

    LLVMFuzzerTestOneInput_911(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
