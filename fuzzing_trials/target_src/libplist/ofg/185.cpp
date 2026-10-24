#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int plist_int_val_compare(plist_t plist, int64_t value);

extern "C" int LLVMFuzzerTestOneInput_185(const uint8_t *data, size_t size) {
    // Ensure there's enough data to create a plist integer node
    if (size < sizeof(int64_t)) {
        return 0;
    }
    
    // Create a plist integer node
    plist_t plist_node = plist_new_int(*(int64_t*)data);
    
    // Use the rest of the data as the int64_t value for comparison
    int64_t compare_value = 0;
    if (size >= sizeof(int64_t) * 2) {
        compare_value = *(int64_t*)(data + sizeof(int64_t));
    }

    // Call the function-under-test
    int result = plist_int_val_compare(plist_node, compare_value);

    // Clean up
    plist_free(plist_node);

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

    LLVMFuzzerTestOneInput_185(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
