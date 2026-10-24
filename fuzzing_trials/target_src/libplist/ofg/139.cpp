#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Initialize the plist object
    plist_t plist = plist_new_dict();
    
    // Add a dummy key-value pair to ensure plist is not empty
    plist_dict_set_item(plist, "dummy_key", plist_new_uint(size));

    // Initialize a uint64_t variable to store the result
    uint64_t value = 0;

    // Call the function-under-test
    plist_get_uint_val(plist, &value);

    // Free the plist object
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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
