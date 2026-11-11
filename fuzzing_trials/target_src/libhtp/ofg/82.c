#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "/src/libhtp/htp/bstr.h" // Correct path for the bstr.h header file

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a bstr and a C string
    if (size < 2) {
        return 0;
    }

    // Create a bstr instance
    bstr bstr_instance;
    bstr_instance.realptr = (unsigned char *)data;
    bstr_instance.len = size / 2; // Use half of the data for bstr
    bstr_instance.size = bstr_instance.len; // Assuming no extra buffer space

    // Create a C string from the remaining data
    char c_string[size - bstr_instance.len + 1];
    memcpy(c_string, data + bstr_instance.len, size - bstr_instance.len);
    c_string[size - bstr_instance.len] = '\0'; // Null-terminate the C string

    // Call the function-under-test
    int result = bstr_cmp_c_nocasenorzero(&bstr_instance, c_string);

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

    LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
