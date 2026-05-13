#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    plist_t plist = NULL;
    char *xml = NULL;
    uint32_t xml_size = 0;

    // Create a plist from the input data
    plist_from_bin(reinterpret_cast<const char*>(data), size, &plist);

    // Ensure plist is not NULL
    if (plist == NULL) {
        return 0;
    }

    // Call the function-under-test
    plist_err_t result = plist_to_xml(plist, &xml, &xml_size);

    // Clean up
    if (xml != NULL) {
        free(xml);
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

    LLVMFuzzerTestOneInput_144(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
