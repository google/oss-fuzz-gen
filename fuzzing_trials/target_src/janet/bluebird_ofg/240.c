#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_240(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to create required objects
    if (size < sizeof(JanetKV) + sizeof(Janet) + sizeof(JanetStruct)) {
        return 0;
    }

    // Initialize Janet environment
    janet_init();

    // Allocate and initialize a JanetKV object
    JanetKV *kv = janet_struct_begin(1);
    if (!kv) {
        janet_deinit();
        return 0;
    }

    // Create a Janet object from the input data
    Janet key;
    memcpy(&key, data, sizeof(Janet));

    // Allocate and initialize a JanetStruct object
    JanetStruct *jstruct = janet_struct_end(kv);
    if (!jstruct) {
        janet_deinit();
        return 0;
    }

    // Call the function-under-test
    Janet result = janet_struct_get_ex(jstruct, key, NULL);

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_240(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
