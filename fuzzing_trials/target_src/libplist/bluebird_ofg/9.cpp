#include <sys/stat.h>
#include <string.h>
extern "C" {
    #include "/src/libplist/libcnary/include/node.h"
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    int debug_level = 0;

    // Ensure that the input data can be used to set the debug level
    if (size > 0) {
        debug_level = static_cast<int>(data[0]); // Use the first byte of data as the debug level
    }

    // Call the function-under-test
    plist_set_debug(debug_level);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
