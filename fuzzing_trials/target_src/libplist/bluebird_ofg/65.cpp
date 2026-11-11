#include <sys/stat.h>
#include <string.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "plist/plist.h"

extern "C" {
    #include "plist/plist.h"
}

extern "C" int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a plist object from the input data
    plist_t plist = NULL;
    plist_from_bin((const char*)data, size, &plist);

    // Prepare the output parameters for plist_to_json
    char *json_output = NULL;
    uint32_t json_length = 0;
    int format = 0; // 0 or 1, representing different JSON formats

    // Call the function-under-test
    plist_err_t result = plist_to_json(plist, &json_output, &json_length, format);

    // Clean up
    if (json_output) {
        free(json_output);
    }
    if (plist) {
        plist_free(plist);
    }

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
