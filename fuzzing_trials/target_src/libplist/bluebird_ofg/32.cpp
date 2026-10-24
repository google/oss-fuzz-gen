#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern "C" {
    #include "/src/libplist/libcnary/include/node.h"
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for a null-terminated string
    if (size < 1) return 0;

    // Create a null-terminated string from the input data
    char *key_val = (char *)malloc(size + 1);
    if (key_val == NULL) return 0;
    memcpy(key_val, data, size);
    key_val[size] = '\0';

    // Create a plist object
    plist_t plist = plist_new_dict();
    if (plist == NULL) {
        free(key_val);
        return 0;
    }

    // Create a dummy value to associate with the key
    plist_t value = plist_new_string("dummy_value");
    if (value == NULL) {
        plist_free(plist);
        free(key_val);
        return 0;
    }

    // Set the key-value pair in the plist
    plist_dict_set_item(plist, key_val, value);

    // Optionally, serialize the plist to ensure it is being utilized
    char *plist_xml = NULL;
    uint32_t plist_length = 0;
    plist_to_xml(plist, &plist_xml, &plist_length);

    // Clean up
    if (plist_xml) {
        free(plist_xml);
    }
    plist_free(plist);
    free(key_val);

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
