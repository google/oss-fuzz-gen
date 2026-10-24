// This fuzz driver is generated for library cjson, aiming to fuzz the following functions:
// cJSON_CreateObject at cJSON.c:2609:23 in cJSON.h
// cJSON_AddFalseToObject at cJSON.c:2174:22 in cJSON.h
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
extern "C" {
#include "cJSON.h"
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    // Prepare a buffer for the key name in cJSON_AddFalseToObject
    char keyName[256];
    if (Size > 0) {
        size_t keyLength = Size < 255 ? Size : 255;
        memcpy(keyName, Data, keyLength);
        keyName[keyLength] = '\0'; // Ensure null termination
    } else {
        keyName[0] = '\0'; // Default to empty string if no data
    }

    // Step 1: Create a cJSON object
    cJSON *jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        // If creation failed, return early
        return 0;
    }

    // Step 2: Add a false value to the JSON object
    cJSON *falseItem = cJSON_AddFalseToObject(jsonObject, keyName);
    (void)falseItem; // We don't need to use falseItem, just ensure it's created

    // Step 3: Clean up the cJSON object
    cJSON_Delete(jsonObject);

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
