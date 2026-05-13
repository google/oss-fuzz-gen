extern "C" {
    #include <plist/plist.h>
}

#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a valid plist
    if (size < 1) return 0;

    // Create a plist from the input data
    plist_t plist = plist_new_data((const char*)data, size);
    if (!plist) return 0;

    // Initialize a non-null char pointer
    char *string_val = new char[1];
    string_val[0] = '\0';

    // Call the function-under-test
    plist_get_string_val(plist, &string_val);

    // Clean up
    if (string_val) {
        delete[] string_val;
    }
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

    LLVMFuzzerTestOneInput_115(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
