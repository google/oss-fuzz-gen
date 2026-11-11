#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int plist_uid_val_compare(plist_t plist, uint64_t uid);

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Initialize plist_t
    plist_t plist = plist_new_dict();

    // Add a key-value pair to the plist to ensure it's not NULL
    plist_dict_set_item(plist, "key", plist_new_uint(42));

    // Ensure there is some data to interpret as a uint64_t
    uint64_t uid = 0;
    if (size >= sizeof(uint64_t)) {
        uid = *((uint64_t *)data);
    }

    // Call the function-under-test
    int result = plist_uid_val_compare(plist, uid);

    // Clean up
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
