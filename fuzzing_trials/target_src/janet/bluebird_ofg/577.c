#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

// Ensure that the Janet library is initialized properly
void initialize_janet_577() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput_577(const uint8_t *data, size_t size) {
    // Ensure there is enough data to proceed
    if (size < sizeof(JanetKV)) {
        return 0;
    }

    // Initialize Janet environment
    initialize_janet_577();

    // Allocate memory for JanetKV array
    size_t kv_count = size / sizeof(JanetKV);
    JanetKV *kvs = (JanetKV *)malloc(kv_count * sizeof(JanetKV));

    // Copy data into the JanetKV array
    for (size_t i = 0; i < kv_count; i++) {
        kvs[i].key = janet_wrap_integer(data[i % size]);
        kvs[i].value = janet_wrap_integer(data[(i + 1) % size]);
    }

    // Create a JanetStruct from the JanetKV array
    const Janet *janetStruct = janet_struct_begin(kv_count);
    for (size_t i = 0; i < kv_count; i++) {
        janet_struct_put(janetStruct, kvs[i].key, kvs[i].value);
    }
    JanetStruct finalStruct = janet_struct_end(janetStruct);

    // Call the function-under-test
    JanetStructHead *head = janet_struct_head(finalStruct);

    // Clean up
    free(kvs);

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

    LLVMFuzzerTestOneInput_577(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
