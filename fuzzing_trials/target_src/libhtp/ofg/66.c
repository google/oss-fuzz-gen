#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "/src/libhtp/htp/bstr.h" // Correct path for bstr.h

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a bstr and a memory block
    if (size < 2) {
        return 0;
    }

    // Create a bstr structure
    bstr bstr_instance;
    bstr_instance.realptr = (unsigned char *)data;
    bstr_instance.len = size / 2; // Use half of the input data for bstr
    bstr_instance.size = bstr_instance.len; // Assuming the current size is the same as length

    // Create a memory block for comparison
    const void *mem_block = data + bstr_instance.len;
    size_t mem_size = size - bstr_instance.len;

    // Call the function-under-test
    int result = bstr_begins_with_mem_nocase(&bstr_instance, mem_block, mem_size);

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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
