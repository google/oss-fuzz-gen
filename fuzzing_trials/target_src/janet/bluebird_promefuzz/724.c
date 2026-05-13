#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void fuzz_janet_bytes_view(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet x = *(Janet *)Data;
    const uint8_t *data;
    int32_t len;
    janet_bytes_view(x, &data, &len);
}

static void fuzz_janet_unwrap_string(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet x = *(Janet *)Data;
    janet_unwrap_string(x);
}

static void fuzz_janet_string_begin(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t length = *(int32_t *)Data;
    if (length < 0) return;
    uint8_t *str = janet_string_begin(length);
    if (str) {
        memset(str, 0, length);
        janet_string_end(str);
    }
}

static void fuzz_janet_string(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return;
    int32_t len = *(int32_t *)Data;
    if (len < 0 || len > (int32_t)(Size - sizeof(int32_t))) return;
    const uint8_t *buf = Data + sizeof(int32_t);
    janet_string(buf, len);
}

static void fuzz_janet_to_string(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet x = *(Janet *)Data;
    janet_to_string(x);
}

int LLVMFuzzerTestOneInput_724(const uint8_t *Data, size_t Size) {
    janet_init();

    fuzz_janet_bytes_view(Data, Size);
    fuzz_janet_unwrap_string(Data, Size);
    fuzz_janet_string_begin(Data, Size);
    fuzz_janet_string(Data, Size);
    fuzz_janet_to_string(Data, Size);

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

    LLVMFuzzerTestOneInput_724(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
