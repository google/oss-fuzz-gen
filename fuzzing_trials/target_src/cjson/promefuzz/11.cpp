// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_Parse at cJSON.c:1227:23 in cJSON.h
// cJSON_GetErrorPtr at cJSON.c:94:28 in cJSON.h
// cJSON_GetObjectItemCaseSensitive at cJSON.c:1988:23 in cJSON.h
// cJSON_IsString at cJSON.c:3032:26 in cJSON.h
// cJSON_GetObjectItemCaseSensitive at cJSON.c:1988:23 in cJSON.h
// cJSON_IsNumber at cJSON.c:3022:26 in cJSON.h
// cJSON_GetObjectItemCaseSensitive at cJSON.c:1988:23 in cJSON.h
// cJSON_IsNumber at cJSON.c:3022:26 in cJSON.h
// cJSON_Delete at cJSON.c:253:20 in cJSON.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "cJSON.h"

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Ensure the data is null-terminated
    char *json_input = static_cast<char*>(malloc(Size + 1));
    if (!json_input) {
        return 0;
    }
    memcpy(json_input, Data, Size);
    json_input[Size] = '\0';

    // Step 1: Parse the JSON input
    cJSON *json = cJSON_Parse(json_input);
    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != nullptr) {
            // Handle parse error if needed
        }
        free(json_input);
        return 0;
    }

    // Step 2: Retrieve an item by key (case-sensitive)
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, "key1");
    if (item && cJSON_IsString(item)) {
        // Process the string item if needed
    }

    // Step 3: Retrieve another item by key (case-sensitive)
    item = cJSON_GetObjectItemCaseSensitive(json, "key2");
    if (item && cJSON_IsNumber(item)) {
        // Process the number item if needed
    }

    // Step 4: Retrieve yet another item by key (case-sensitive)
    item = cJSON_GetObjectItemCaseSensitive(json, "key3");
    if (item && cJSON_IsNumber(item)) {
        // Process the number item if needed
    }

    // Cleanup
    cJSON_Delete(json);
    free(json_input);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
