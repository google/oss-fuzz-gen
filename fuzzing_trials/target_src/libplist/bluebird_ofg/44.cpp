#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for the test
    if (size < 2) return 0;

    // Initialize plist object
    plist_t plist = plist_new_string("test_string");

    // Create a null-terminated string for comparison
    size_t str_size = size - 1; // Ensure space for null terminator
    char *str = (char *)malloc(str_size + 1);
    if (!str) return 0;

    memcpy(str, data, str_size);
    str[str_size] = '\0';

    // Call the function-under-test
    plist_string_val_compare_with_size(plist, str, str_size);

    // Clean up
    free(str);
    plist_free(plist);

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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
