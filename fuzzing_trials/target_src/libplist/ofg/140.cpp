#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the XML string and ensure it's null-terminated
    char *xml_data = (char *)malloc(size + 1);
    if (xml_data == NULL) {
        return 0;
    }
    memcpy(xml_data, data, size);
    xml_data[size] = '\0';

    // Initialize plist_t variable
    plist_t plist = NULL;

    // Call the function-under-test
    plist_err_t result = plist_from_xml(xml_data, (uint32_t)size, &plist);

    // Clean up
    if (plist != NULL) {
        plist_free(plist);
    }
    free(xml_data);

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

    LLVMFuzzerTestOneInput_140(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
