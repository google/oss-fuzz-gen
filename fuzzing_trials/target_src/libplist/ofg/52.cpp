#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for testing
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the input string and ensure null-termination
    char *input_str = (char *)malloc(size + 1);
    if (!input_str) {
        return 0;
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0';  // Null-terminate the string

    // Initialize variables for the function call
    plist_t plist = NULL;
    plist_format_t format = PLIST_FORMAT_XML;
    uint32_t length = (uint32_t)size;

    // Call the function-under-test
    plist_err_t result = plist_from_memory(input_str, length, &plist, &format);

    // Clean up
    if (plist) {
        plist_free(plist);
    }
    free(input_str);

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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
