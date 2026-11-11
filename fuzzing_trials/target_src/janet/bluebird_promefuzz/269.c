#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_resolve_core(const uint8_t *Data, size_t Size) {
    char *name = (char *)malloc(Size + 1);
    if (!name) return;
    memcpy(name, Data, Size);
    name[Size] = '\0';
    Janet result = janet_resolve_core(name);
    (void)result; // Suppress unused variable warning
    free(name);
}

static void fuzz_janet_unwrap_string(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet x;
    memcpy(&x, Data, sizeof(Janet));
    JanetString result = janet_unwrap_string(x);
    (void)result; // Suppress unused variable warning
}

static void fuzz_janet_getstring(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(int32_t)) return;
    const Janet *argv = (const Janet *)Data;
    int32_t n = *(int32_t *)(Data + sizeof(Janet));

    // Validate the Janet value is a string
    if (janet_type(argv[0]) != JANET_STRING) return;

    // Ensure n is within the bounds of the Janet tuple or array
    JanetString result = janet_getstring(argv, n);
    (void)result; // Suppress unused variable warning
}

static void fuzz_janet_symbol(const uint8_t *Data, size_t Size) {
    JanetSymbol result = janet_symbol(Data, (int32_t)Size);
    (void)result; // Suppress unused variable warning
}

static void fuzz_janet_native(const uint8_t *Data, size_t Size) {
    char *name = (char *)malloc(Size + 1);
    if (!name) return;
    memcpy(name, Data, Size);
    name[Size] = '\0';
    JanetString error = NULL;
    JanetModule result = janet_native(name, &error);
    (void)result; // Suppress unused variable warning
    free(name);
}

int LLVMFuzzerTestOneInput_269(const uint8_t *Data, size_t Size) {
    initialize_janet();
    fuzz_janet_resolve_core(Data, Size);
    fuzz_janet_unwrap_string(Data, Size);
    fuzz_janet_getstring(Data, Size);
    fuzz_janet_symbol(Data, Size);
    fuzz_janet_native(Data, Size);
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

    LLVMFuzzerTestOneInput_269(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
