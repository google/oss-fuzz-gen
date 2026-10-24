#include <sys/stat.h>
#include <string.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    #include "plist/plist.h"

    int plist_uid_val_compare(plist_t node, uint64_t value);
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    plist_t node = nullptr;
    uint64_t uid_value = 0;

    if (size > 0) {
        // Create a plist node from the input data
        plist_from_bin((const char *)data, size, &node);
    }

    // Ensure node is not null
    if (node == nullptr) {
        // If node creation failed, create a default node
        node = plist_new_uid(0);
    }

    // Extract a uint64_t value from the input data if possible
    if (size >= sizeof(uint64_t)) {
        memcpy(&uid_value, data, sizeof(uint64_t));
    }

    // Call the function-under-test
    int result = plist_uid_val_compare(node, uid_value);

    // Clean up
    plist_free(node);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
