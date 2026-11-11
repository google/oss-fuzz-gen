#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient
    if (size < 1) {
        return 0;
    }

    // Initialize plist
    plist_t plist = plist_new_dict();

    // Create a key and value from the input data
    char key[] = "fuzz_key";
    char value[size + 1];
    memcpy(value, data, size);
    value[size] = '\0';

    // Add the key-value pair to the plist
    plist_dict_set_item(plist, key, plist_new_string(value));

    // Prepare output variables for plist_to_xml
    char *xml = NULL;
    uint32_t xml_size = 0;

    // Call the function-under-test
    plist_err_t err = plist_to_xml(plist, &xml, &xml_size);

    // Clean up
    if (xml) {
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

    LLVMFuzzerTestOneInput_145(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
