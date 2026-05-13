#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static Janet create_janet_number(double num) {
    Janet j;
    j.number = num;
    return j;
}

static Janet create_janet_file(FILE *file) {
    // Assume janet_wrap_abstract is a function to wrap a file into a Janet abstract type
    return janet_wrap_abstract(file);
}

static Janet create_janet_pointer(void *ptr) {
    Janet j;
    j.pointer = ptr;
    return j;
}

int LLVMFuzzerTestOneInput_532(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0;

    // Initialize Janet VM
    janet_init();

    // Test janet_unwrap_number
    double num = *(double *)Data;
    Janet janet_num = create_janet_number(num);
    double result_num = janet_unwrap_number(janet_num);

    // Test janet_unwrapfile
    FILE *dummy_file = fopen("./dummy_file", "w+");
    if (dummy_file) {
        Janet janet_file = create_janet_file(dummy_file);
        int32_t flags = 0;
        FILE *result_file = janet_unwrapfile(janet_file, &flags);
        fclose(dummy_file);
    }

    // Test janet_asm
    Janet source;
    source.u64 = 0; // Assuming a valid Janet source is created here
    int flags = 0;
    JanetAssembleResult asm_result = janet_asm(source, flags);

    // Test janet_unwrap_pointer
    void *ptr = (void *)(Data + sizeof(double));
    Janet janet_ptr = create_janet_pointer(ptr);
    void *result_ptr = janet_unwrap_pointer(janet_ptr);

    // Cleanup Janet VM
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

    LLVMFuzzerTestOneInput_532(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
