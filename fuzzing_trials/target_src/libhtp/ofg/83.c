#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Include this for malloc and free
#include "/src/libhtp/htp/bstr.h" // Correct path for the bstr.h header

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    bstr bstr_instance;
    char *cstr = NULL;

    // Ensure there is enough data to work with
    if (size < 2) {
        return 0;
    }

    // Initialize bstr_instance with a portion of the data
    bstr_instance.realptr = (unsigned char *)data;
    bstr_instance.len = size / 2; // Use half of the data for bstr
    bstr_instance.size = bstr_instance.len; // Assume the buffer size is the same as the length

    // Initialize cstr with the remaining portion of the data
    cstr = (char *)(data + bstr_instance.len);
    
    // Ensure cstr is null-terminated
    size_t cstr_len = size - bstr_instance.len;
    char *cstr_null_terminated = (char *)malloc(cstr_len + 1);
    if (cstr_null_terminated == NULL) {
        return 0;
    }
    memcpy(cstr_null_terminated, cstr, cstr_len);
    cstr_null_terminated[cstr_len] = '\0';

    // Call the function-under-test
    int result = bstr_cmp_c_nocasenorzero(&bstr_instance, cstr_null_terminated);

    // Clean up
    free(cstr_null_terminated);

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

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
