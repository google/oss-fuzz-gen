#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "/src/libhtp/htp/bstr.h" // Correct path for bstr.h

// Function-under-test
int bstr_cmp_mem_nocase(const bstr *b, const void *mem, size_t len);

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to perform meaningful fuzzing
    }

    // Initialize a bstr object
    bstr b;
    b.realptr = (unsigned char *)data;
    b.len = size / 2; // Use half of the data for bstr
    b.size = b.len; // Assuming the buffer size is the same as the length

    // Use the other half of the data for the memory buffer
    const void *mem = data + b.len;
    size_t mem_len = size - b.len;

    // Call the function-under-test
    int result = bstr_cmp_mem_nocase(&b, mem, mem_len);

    // Use the result in some way to prevent compiler optimizations
    (void)result;

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
