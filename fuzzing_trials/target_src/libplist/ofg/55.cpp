#include <stdint.h>
#include <stddef.h>

extern "C" {
    void plist_set_debug(int debug_level);
}

extern "C" int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    int debug_level = 0;

    if (size > 0) {
        // Use the first byte of data to determine the debug level
        debug_level = static_cast<int>(data[0]);
    }

    // Call the function-under-test with the determined debug level
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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
