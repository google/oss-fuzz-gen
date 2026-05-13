#include <sys/stat.h>
#include <string.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "plist/plist.h"

extern "C" {
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < sizeof(uint32_t) + 1) {
        return 0;
    }

    // Initialize plist
    plist_t plist = plist_new_dict();

    // Extract a uint32_t value from the data
    uint32_t index;
    memcpy(&index, data, sizeof(uint32_t));

    // Prepare a dummy path (void*), using the remaining data
    // Ensure the path is null-terminated to prevent overflow in string functions
    size_t path_size = size - sizeof(uint32_t);
    char *path = new char[path_size + 1];
    memcpy(path, data + sizeof(uint32_t), path_size);
    path[path_size] = '\0'; // Null-terminate

    // Call the function-under-test
    plist_t result = plist_access_path(plist, index, path);

    // Clean up
    plist_free(plist);
    plist_free(result);
    delete[] path;

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
