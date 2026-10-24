#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "/src/json-c/json_tokener.h"

extern "C" int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a new json_tokener with a specified depth
    int depth = Data[0] % 10 + 1; // Ensure depth is at least 1
    struct json_tokener *tok = json_tokener_new_ex(depth);
    if (!tok) return 0;

    // Set flags for the tokener
    int flags = Data[0] % 256; // Use the first byte as flags
    json_tokener_set_flags(tok, flags);

    // Attempt to parse the input data
    const char *json_data = reinterpret_cast<const char*>(Data);
    size_t json_data_size = Size;
    json_tokener_parse_ex(tok, json_data, json_data_size);

    // Get the error status
    enum json_tokener_error error = json_tokener_get_error(tok);

    // Reset the tokener to allow re-use
    json_tokener_reset(tok);

    // Free the tokener
    json_tokener_free(tok);

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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
