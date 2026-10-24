#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include the string.h header for memcpy

extern "C" {
    #include <plist/plist.h>

    plist_err_t plist_from_memory(const char *, uint32_t, plist_t *, plist_format_t *);
}

extern "C" int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for the function parameters
    if (size < 1) return 0;

    // Convert the input data to a null-terminated string
    char *input_data = (char *)malloc(size + 1);
    if (!input_data) return 0;
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Initialize the plist_t and plist_format_t variables
    plist_t plist = NULL;
    plist_format_t format = PLIST_FORMAT_XML;

    // Call the function-under-test
    plist_err_t result = plist_from_memory(input_data, (uint32_t)size, &plist, &format);

    // Clean up
    if (plist) plist_free(plist);
    free(input_data);

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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
