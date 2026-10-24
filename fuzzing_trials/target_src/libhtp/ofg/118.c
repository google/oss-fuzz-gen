#include <stdint.h>
#include <stddef.h>
#include "/src/libhtp/htp/bstr.h" // Correct path for the bstr header file

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Ensure there's enough data for a meaningful test
    if (size < 2) {
        return 0;
    }

    // Initialize a bstr object
    struct bstr_t bstr_obj; // Use 'struct' tag to refer to type 'bstr_t'
    bstr_obj.realptr = (unsigned char *)data;
    bstr_obj.len = size / 2; // Use half of the data for bstr
    bstr_obj.size = bstr_obj.len; // Set the size to the length for simplicity

    // Use the rest of the data for the memory buffer
    const void *mem_buf = data + bstr_obj.len;
    size_t mem_size = size - bstr_obj.len;

    // Call the function-under-test
    int result = bstr_begins_with_mem(&bstr_obj, mem_buf, mem_size);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
