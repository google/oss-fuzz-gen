#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "/src/libhtp/htp/bstr.h" // Correct path for bstr.h

// Remove the extern "C" linkage specification for C++ compatibility
int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    if (size < 2) {
        // Not enough data to create two bstr objects
        return 0;
    }

    // Split the input data into two parts for two bstr objects
    size_t mid = size / 2;

    // Create and initialize the first bstr object
    bstr str1;
    str1.realptr = (unsigned char *)data;
    str1.len = mid;
    str1.size = mid; // Assuming the buffer size is the same as the length

    // Create and initialize the second bstr object
    bstr str2;
    str2.realptr = (unsigned char *)(data + mid);
    str2.len = size - mid;
    str2.size = size - mid; // Assuming the buffer size is the same as the length

    // Call the function-under-test
    int result = bstr_begins_with_nocase(&str1, &str2);

    // Return 0 to indicate the fuzzer should continue
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_143(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
