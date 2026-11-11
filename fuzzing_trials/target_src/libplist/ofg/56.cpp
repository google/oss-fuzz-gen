#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Initialize plist_t
    plist_t plist = NULL;
    plist_format_t format = PLIST_FORMAT_XML; // Assuming a default format

    // Adjust the function call to include the format parameter
    plist_from_memory((const char*)data, size, &plist, &format);

    // Initialize char* for output
    char *openstep_str = NULL;

    // Initialize uint32_t for length
    uint32_t length = 0;

    // Set a non-zero value for the int parameter
    int options = 1;

    // Call the function-under-test
    plist_err_t result = plist_to_openstep(plist, &openstep_str, &length, options);

    // Clean up
    if (openstep_str != NULL) {
        free(openstep_str);
    }
    if (plist != NULL) {
        plist_free(plist);
    }

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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
